//Global variables
let clientPermanentPublicKeyXHex = null;
let clientPermanentPublicKeyYHex = null;
let clientPermanentPrivateKey = null;
let recipientPublicKeyXHex = null;
let recipientPublicKeyYHex = null;

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

function readFileDataURL(file) {
  return new Promise((resolve) => {
    let reader = new FileReader();
    reader.onload = () => {
      resolve(reader.result.replace(/^data:.+;base64,/, ''));
      //resolve(reader.result);
    };
    reader.readAsDataURL(file);
    console.log("File read as data URL");
  });
}

/*const b64toBlob = (b64Data, contentType='', sliceSize=512) => {
  const byteCharacters = atob(b64Data);
  const byteArrays = [];

  for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
    const slice = byteCharacters.slice(offset, offset + sliceSize);

    const byteNumbers = new Array(slice.length);
    for (let i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }

    const byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }

  const blob = new Blob(byteArrays, {type: contentType});
  return blob;
}*/

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
    let tempClientPermanentPrivateKey = await window.crypto.subtle.exportKey(
      "jwk",
      clientPermanentPrivateKey
    );
    sessionStorage.setItem(
      "clientPermanentPrivateKey",
      JSON.stringify(tempClientPermanentPrivateKey)
    );

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
        window.location.replace(`${window.origin}/index`);
      });
    });
  }
}

function encryptAndSend() {
  //Depends on the front-end
  let recipientUserName = document.getElementById("username");
  let userFile = document.getElementById("userFile");
  let sendBtn = document.getElementById("send");

  sendBtn.addEventListener("click", () => {
    console.log("Encrypt and send process initiated");
    //encryption();
    receive_key();
  });

  function receive_key() {
    let req_json = { username: `${recipientUserName.value}` };
    fetch(`${window.origin}/send_request`, {
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
        console.log(typeof data);
        recipientPublicKeyXHex = data.public_keyX;
        recipientPublicKeyYHex = data.public_keyY;
        console.log(recipientPublicKeyXHex);
        console.log(recipientPublicKeyYHex);
        //return data;
        encryption(recipientPublicKeyXHex, recipientPublicKeyYHex);
      });
    });
  }
  async function encryption(recipientPublicKeyXHex, recipientPublicKeyYHex) {
    /* Fetch the recipient's public keys from server/database
        recipientPublicKeyXHex = 
        recipientPublicKeyYHex = 
        */

    /*let req_json = { username: `${recipientUserName.value}` };
      fetch(`${window.origin}/send_request`, {
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
        console.log(typeof data);
        recipientPublicKeyXHex = data.public_keyX;
        recipientPublicKeyYHex = data.public_keyY;
        console.log(recipientPublicKeyXHex);
        console.log(recipientPublicKeyYHex);
        //return data;
      });
    });*/
    //console.log(data);
    //recipientPublicKeyXHex = data.public_keyX;
    //recipientPublicKeyYHex = data.public_keyY;

    var recipientPublicKeyXb64url = Uint8ArrayToBase64URLString(
      HexStringToUint8Array(recipientPublicKeyXHex)
    );
    var recipientPublicKeyYb64url = Uint8ArrayToBase64URLString(
      HexStringToUint8Array(recipientPublicKeyYHex)
    );
    var recipientPublicKeyJwk =
      '{"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"' +
      recipientPublicKeyXb64url +
      '","y":"' +
      recipientPublicKeyYb64url +
      '"}';
    var recipientPublicKey = await window.crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(recipientPublicKeyJwk),
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        []
      )
      .catch((err) => {
        console.error(err);
      });
    console.log("Recipient's public key imported.");
    console.log(sessionStorage.getItem("clientPermanentPrivateKey"));
    let tempClientPermanentPrivateKey = sessionStorage.getItem(
      "clientPermanentPrivateKey"
    );
    var clientPermanentPrivateKey = await window.crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(tempClientPermanentPrivateKey),
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey"]
      )
      .catch((err) => {
        console.error(err);
      });
    var encryptionKey = await window.crypto.subtle
      .deriveKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
          public: recipientPublicKey,
        },
        clientPermanentPrivateKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["encrypt"]
      )
      .catch((err) => {
        console.error(err);
      });
    console.log("Encryption key derived.");

    let userFileContent = await readFile(userFile.files[0]);
    let userEncodedFile = new Uint8Array(userFileContent);
    let iv = window.crypto.getRandomValues(new Uint8Array(12));
    let userEncryptedFileArrayBuffer = await window.crypto.subtle
      .encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        encryptionKey,
        userEncodedFile
      )
      .catch((err) => {
        console.log(err);
      });
    console.log("File encrypted");
    //userEncryptedFile = Uint8ArrayToHexString(new Uint8Array(userEncryptedFileArrayBuffer));
    //let userEncryptedFileHex = Uint8ArrayToHexString(new Uint8Array(userEncryptedFileArrayBuffer));
    // It might be possible that the following approach won't work. In such a case,
    // see encryptedsend's implementation involving AppendArrays function.
    console.log(iv);
    console.log(new Uint8Array(userEncryptedFileArrayBuffer));
    console.log(userEncryptedFileArrayBuffer);
    let payload = new Blob([iv, new Uint8Array(userEncryptedFileArrayBuffer)], {
      type: "application/octet-stream",
    });

    //var reader = new FileReader(); 
    //var userEncryptedFile;
    /*reader.readAsDataURL(payload); 
    reader.onloadend = async function () { 
    userEncryptedFile = await reader.result; 
    //console.log('Base64 String - ', userEncryptedFile);
    }*/
    let userEncryptedFile = await readFileDataURL(payload);

    sendFile(userEncryptedFile);
    //Send this payload to a database/server.
    
    
    /*let payloadForm = new FormData();
    payloadForm.append('username', `${recipientUserName.value}`);
    payloadForm.append('file', payload);*/
    function sendFile(userEncryptedFile){
      console.log(userEncryptedFile);
      console.log(userFile.files[0].name);
      let payload_json = {
        payload: userEncryptedFile,
        payloadName: userFile.files[0].name,
        username: `${recipientUserName.value}`
      };
      fetch(`${window.origin}/get_payload`, {
        method: "POST",
        credentials: "include",
        body: JSON.stringify(payload_json),
        cache: "no-cache",
        headers: new Headers({
          "X-CSRFToken": getCookie("csrftoken"),
          "content-type": "false",
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
    }
  }
    
}


function receiveAndDecrypt() {
  //Depends on the front-end. Add an eventlistener.
  let downloadBtn = document.getElementById("download");
  //Fetch the files of the user from the database/server
  let userFiles = null;
  fetch(`${window.origin}/get_received_files`)
  .then((res)=>{res.json().then((data)=>{console.log(data.filename);
  downloadBtn.addEventListener("click", () => {
        console.log("Decryption process initiated.");
        receive_key(data.userFiles, data.filename);})})});
  // .then((data) => {userFiles = data.userFiles; console.log(userFiles)});
  // .then(
  // .then(() => {
  //   downloadBtn.addEventListener("click", () => {
  //     console.log("Decryption process initiated.");
  //     receive_key(userFiles);
    // });
  // }));
  
  

  //console.log("User files received.");
  /*async function getFiles(){
    let response = await fetch(`${window.origin}/get_received_files`);
    let tempUserFiles = await response.json();
    console.log(tempUserFiles);
    return tempUserFiles;
    response.then(function (response) {
    response.json().then(function (data) {
      console.log(data);
      userFiles = data.userFiles;
      console.log(userFiles);
      //setuserfiles(data.userFiles);
    });
  });
  }*/
 // userFiles = getFiles();
// console.log(userFiles);
// let response = fetch(`${window.origin}/get_received_files`);
// (async () => userFiles = await response.json());
//   response.then(function (response) {
//     response.json().then(function (data) {
//       console.log(data);
//       userFiles = data.userFiles;
//       console.log(userFiles);
//       //setuserfiles(data.userFiles);
//     });
//   });

  /*function setuserfiles(userFiles){
        userFiles = this.userFiles;
        console.log(userFiles);
  }*/
  //console.log(userFiles);

  // downloadBtn.addEventListener("click", () => {
  //   console.log("Decryption process initiated.");
  //   receive_key();
  // });
  
function receive_key(userFiles, filename){
  let response = fetch(`${window.origin}/get_senderpublickey`);
    response.then(function (response) {
      response.json().then(function (data) {
        console.log(data);
        senderPublicKeyXHex = data.public_keyX;
        senderPublicKeyYHex = data.public_keyY;
        console.log(senderPublicKeyXHex);
        decryption(senderPublicKeyXHex, senderPublicKeyYHex, userFiles, filename);
      });
    });

}
  async function decryption(senderPublicKeyXHex, senderPublicKeyYHex, userFiles, filename) {
    /* Fetch the sender's public key from database/server
        senderPublicKeyXHex = 
        senderPublicKeyYHex = 
        */
    console.log(senderPublicKeyXHex);
    var senderPublicKeyXb64url = Uint8ArrayToBase64URLString(
      HexStringToUint8Array(senderPublicKeyXHex)
    );
    var senderPublicKeyYb64url = Uint8ArrayToBase64URLString(
      HexStringToUint8Array(senderPublicKeyYHex)
    );
    var senderPublicKeyJwk =
      '{"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"' +
      senderPublicKeyXb64url +
      '","y":"' +
      senderPublicKeyYb64url +
      '"}';
    var senderPublicKey = await window.crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(senderPublicKeyJwk),
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        []
      )
      .catch((err) => {
        console.error(err);
      });
    console.log("Sender's public key imported.");
    let tempClientPermanentPrivateKey = sessionStorage.getItem(
      "clientPermanentPrivateKey"
    );
    var clientPermanentPrivateKey = await window.crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(tempClientPermanentPrivateKey),
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey"]
      )
      .catch((err) => {
        console.error(err);
      });
    var decryptionKey = await window.crypto.subtle
      .deriveKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
          public: senderPublicKey,
        },
        clientPermanentPrivateKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["decrypt"]
      )
      .catch((err) => {
        console.error(err);
      });
    console.log("Decryption key derived.");

    console.log(userFiles);
    let userFileContent = Base64URLStringToUint8Array(userFiles);
    //let userFileContent = new Uint8Array(await readFile(userFiles));
    //let userFileContent = b64toBlob(userFiles, 'application/octet-stream');
    console.log(userFileContent);
    let iv = new Uint8Array(userFileContent.slice(0, 12));
    let userEncryptedFile = userFileContent.slice(12);
    console.log(iv);
    console.log(userEncryptedFile);
    let userDecryptedFile = await window.crypto.subtle
      .decrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        decryptionKey,
        userEncryptedFile
      )
      .catch((err) => {
        console.log(err);
      });
    console.log("File decrypted and download initiated");

    //Initiate the download process
    var blob = new Blob([new Uint8Array(userDecryptedFile)], {
      type: "application/octet-stream",
    });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", filename); //Error here ?
    link.click();
  }
}
if (`${window.location}` == `${window.origin}/register`) register();
else if (`${window.location}` == `${window.origin}/login`) login();
else if (`${window.location}` == `${window.origin}/send_file`) encryptAndSend();
else if (`${window.location}` == `${window.origin}/received_file`)
  receiveAndDecrypt();
else console.log("No Javacript for this route");
