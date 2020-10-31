let passPhrase = document.getElementById("Passphrase");
let secretFileBtn = document.getElementById("secret");
let userName = document.getElementById("Username");

secretFileBtn.addEventListener("click", () => createSecretFile());

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
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

async function createSecretFile() {
  let encodedPassPhrase = new TextEncoder("utf-8").encode(Passphrase.value);

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
    "raw",
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

  //Downloading the secret file
  var blob = new Blob(
    [
      IntegerToUint8Array(iterations),
      iv,
      salt,
      ecdhPublicKey,
      wrappedEcdhPrivateKey,
    ],
    { type: "application/octet-stream" }
  );
  var url = URL.createObjectURL(blob);
  var link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "Secret Key File.key");
  link.click();
  req_json = { username: userName.value, public_key: ecdhPublicKey};
  //As soon as the register button is clicked, A post request should me initiated which
  //sends the username and the corresponding publickey to the server/database
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
  //To Send: username, ecdhPublicKey (which is in raw form)
}