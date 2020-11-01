//Global variables
var clientPermanentPublicKeyXHex = null;
var clientPermanentPublicKeyYHex = null;
var clientPermanentPrivateKey = null;
var recipientPublicKeyXHex = null;
var recipientPublicKeyYHex = null;

//Useful Functions
function readFile(file) {
  return new Promise((resolve) => {
    let reader = new FileReader();
    reader.onload = () => {
      resolve(reader.result);
    };
    reader.readAsArrayBuffer(file);
    console.log("File read as ArrayBuffer");
  });
}

function getCookie(name) {
  var cookieValue = null;
  if (document.cookie && document.cookie != "") {
    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++) {
      var cookie = jQuery.trim(cookies[i]);
      // Does this cookie string begin with the name we want?
      if (cookie.substring(0, name.length + 1) == name + "=") {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

function IntegerToUint8Array(int) {
  //Converts integer to 4 bytes of Uint8Array
  var r = int,
    result = new Uint8Array(4);
  for (i = 0; i <= 3; i++) {
    result[3 - i] = Math.floor(r / Math.pow(256, i));
    r -= result[3 - i] * Math.pow(256, i);
  }
  return result;
}

function Uint8ArrayToInteger(ui8array) {
  //Converts 4 bytes of Uint8Array to an integer
  var r = 0;
  for (var i = 0; i < ui8array.length; i++) {
    r += ui8array[ui8array.length - i - 1] * Math.pow(256, i);
  }
  return r;
}

function Uint8ArrayToHexString(ui8array) {
  var hexstring = "",
    h;
  for (var i = 0; i < ui8array.length; i++) {
    h = ui8array[i].toString(16);
    if (h.length == 1) {
      h = "0" + h;
    }
    hexstring += h;
  }

  //pad hex string with leading zeroes to make its length 2^n.
  var p = Math.pow(2, Math.ceil(Math.log2(hexstring.length)));
  hexstring = hexstring.padStart(p, "0");

  return hexstring;
}

function Uint8ArrayToBase64String(ui8array) {
  var binary = "";
  for (var i = 0; i < ui8array.byteLength; i++) {
    binary += String.fromCharCode(ui8array[i]);
  }
  return window.btoa(binary);
}

function HexStringToUint8Array(hexstring) {
  var result = new Uint8Array(hexstring.length / 2);
  for (var i = 0; i < hexstring.length / 2; i++) {
    result[i] = parseInt(hexstring.substring(i * 2, i * 2 + 2), 16);
  }
  return result;
}

function Base64StringToUint8Array(base64string) {
  var binary = window.atob(base64string);
  var result = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    result[i] = binary.charCodeAt(i);
  }
  return result;
}

function Uint8ArrayToBase64URLString(ui8array) {
  var result = Uint8ArrayToBase64String(ui8array);
  result = result.replace(/\+/g, "-");
  result = result.replace(/\//g, "_");
  result = result.replace(/=/g, "");
  return result;
}

function Base64URLStringToUint8Array(base64urlstring) {
  var result = base64urlstring;
  result = result.replace(/-/g, "+");
  result = result.replace(/_/g, "/");
  result = Base64StringToUint8Array(result);
  return result;
}

function register() {
  let passPhrase = document.getElementById("Passphrase");
  let secretFileBtn = document.getElementById("secret");
  let userName = document.getElementById("Username");

  async function createSecretFile() {
    let encodedPassPhrase = new TextEncoder("utf-8").encode(passPhrase.value);

    let passPhraseKey = await window.crypto.subtle
      .importKey("raw", encodedPassPhrase, "PBKDF2", false, ["deriveKey"])
      .catch((err) => {
        console.log(err);
      });
    console.log("Passphase key imported");

    let ecdhKeyPair = await window.crypto.subtle
      .generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey"]
      )
      .catch((err) => {
        console.log(err);
      });
    console.log("ECDH key pair generated");

    let salt = window.crypto.getRandomValues(new Uint8Array(16));
    let iterations = 1000000; //Need to change this overtime
    let encryptionKey = await window.crypto.subtle
      .deriveKey(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: salt,
          iterations: iterations,
        },
        passPhraseKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["wrapKey", "encrypt"]
      )
      .catch((err) => {
        console.log(err);
      });
    console.log("Encryption key created");

    //Is "jwk" better over here?
    let ecdhPublicKey = await window.crypto.subtle.exportKey(
      "jwk",
      ecdhKeyPair.publicKey
    );

    let iv = window.crypto.getRandomValues(new Uint8Array(12));
    let wrappedEcdhPrivateKey = await window.crypto.subtle
      .wrapKey("jwk", ecdhKeyPair.privateKey, encryptionKey, {
        name: "AES-GCM",
        iv: iv,
      })
      .catch((err) => {
        console.log(err);
      });
    console.log("Key wrapped");

    //Only for Testing ?
    var ecdhPublicKeyXBytes = Base64URLStringToUint8Array(ecdhPublicKey.x);
    var ecdhPublicKeyYBytes = Base64URLStringToUint8Array(ecdhPublicKey.y);
    var ecdhPublicKeyXHex = Uint8ArrayToHexString(ecdhPublicKeyXBytes);
    var ecdhPublicKeyYHex = Uint8ArrayToHexString(ecdhPublicKeyYBytes);
    console.log("Client Permanent Public Key x: " + ecdhPublicKeyXHex);
    console.log("Client Permanent Public Key y: " + ecdhPublicKeyYHex);

    //Downloading the secret file
    var blob = new Blob(
      [
        IntegerToUint8Array(iterations),
        iv,
        salt,
        ecdhPublicKeyXBytes,
        ecdhPublicKeyYBytes,
        wrappedEcdhPrivateKey,
      ],
      { type: "application/octet-stream" }
    );
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "Secret Key File.key");
    link.click();

    //As soon as the register button is clicked, A post request should me initiated which
    //sends the username and the corresponding publickey to the server/database
    let req_json = {
      username: userName.value,
      public_keyX: ecdhPublicKeyXHex,
      public_keyY: ecdhPublicKeyYHex,
    };
    fetch(`${window.origin}/read_json_data`, {
      method: "POST",
      credentials: "include",
      body: JSON.stringify(req_json),
      cache: "no-cache",
      headers: new Headers({
        "X-CSRFToken": getCookie("csrftoken"),
        "content-type": "application/json",
      }),
    }).then(function (response) {
      if (response.status != 200) {
        console.log(`Response status not 200 : ${response.status}`);
        return;
      }
      response.json().then(function (data) {
        console.log(data);
      });
    });
    //To Send: username, ecdhPublicKeyXHex and ecdhPublicKeyYHex (Both of them are in hex format)
  }
  secretFileBtn.addEventListener("click", () => createSecretFile());
}

function login() {
  let userName = document.getElementById("userName");
  let passPhrase = document.getElementById("Passphrase");
  let uploadBtn = document.getElementById("uploadBtn");
  let secretKeyFile = document.getElementById("secretKeyFile");
  let keyFile;

  secretKeyFile.addEventListener("change", () => {
    console.log("File upload initiated");
    console.log(secretKeyFile.files);
    keyFile = secretKeyFile.files[0];
  });

  uploadBtn.addEventListener("click", () => {
    console.log("Upload method initiated");
    readSecretKeyFile();
  });

  async function readSecretKeyFile() {
    let fileContent = new Uint8Array(await readFile(keyFile));

    let iterations = Uint8ArrayToInteger(fileContent.slice(0, 4));
    let iv = fileContent.slice(4, 16);
    let salt = fileContent.slice(16, 32);
    let ecdhPublicKeyXBytes = fileContent.slice(32, 64);
    let ecdhPublicKeyYBytes = fileContent.slice(64, 96);
    let wrappedEcdhPrivateKey = fileContent.slice(96);

    let encodedPassPhrase = new TextEncoder("utf-8").encode(passPhrase.value);
    let passPhraseKey = await window.crypto.subtle
      .importKey("raw", encodedPassPhrase, "PBKDF2", false, ["deriveKey"])
      .catch((err) => {
        console.log(err);
      });
    console.log("Passphrase key imported");

    let decryptionKey = await window.crypto.subtle
      .deriveKey(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: salt,
          iterations: iterations,
        },
        passPhraseKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["unwrapKey", "decrypt"]
      )
      .catch((err) => {
        console.log(err);
      });
    console.log("Decryption key created");

    clientPermanentPrivateKey = await window.crypto.subtle
      .unwrapKey(
        "jwk",
        wrappedEcdhPrivateKey,
        decryptionKey,
        {
          name: "AES-GCM",
          iv: iv,
        },
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey"]
      )
      .catch((err) => {
        //Write code here to create an alert in the webpage when the passphrase is wrong.
        alert("Passphrase or SecretKeyFile is wrong.");
        console.log(err);
        return;
      });
    console.log("Client's ECDH private key unwrapped and imported");
    //Only for Testing ?
    clientPermanentPublicKeyXHex = Uint8ArrayToHexString(ecdhPublicKeyXBytes);
    clientPermanentPublicKeyYHex = Uint8ArrayToHexString(ecdhPublicKeyYBytes);
    console.log(
      "Client Permanent Public Key x: " + clientPermanentPublicKeyXHex
    );
    console.log(
      "Client Permanent Public Key y: " + clientPermanentPublicKeyYHex
    );
    let req_json = {
      username: userName.value,
      public_keyX: clientPermanentPublicKeyXHex,
      public_keyY: clientPermanentPublicKeyYHex,
    };
    fetch(`${window.origin}/login_successful`, {
      method: "POST",
      credentials: "include",
      body: JSON.stringify(req_json),
      cache: "no-cache",
      headers: new Headers({
        "X-CSRFToken": getCookie("csrftoken"),
        "content-type": "application/json",
      }),
    }).then(function (response) {
      if (response.status != 200) {
        console.log(`Response status not 200 : ${response.status}`);
        return;
      }
      response.json().then(function (data) {
        console.log(data);
        window.location.replace(`${window.origin}/`);
      });
    });
  }
}

if (`${window.location}` == `${window.origin}/register`) register();
else if (`${window.location}` == `${window.origin}/login`) login();
else console.log("Neither Register nor login");