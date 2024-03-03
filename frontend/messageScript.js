document.addEventListener('keydown', handleKeyDown);

function handleKeyDown(event) {

    if (event.keyCode >= 49 && event.keyCode <= 57) {
        var keyNumber = event.keyCode - 48; 
        var pinKey = document.getElementById('pin' + keyNumber + 'key');
        if (pinKey) {
            handlePinKeyClick(pinKey.id);
        }
    }
}

var pinKeys = document.querySelectorAll('.pinkey');

pinKeys.forEach(function(pinKey) {
    pinKey.addEventListener('click', function() {
        handlePinKeyClick(pinKey.id); 
    });
});

function handlePinKeyClick(id) {
    console.log('Kliknięto komórkę o id:', id);

}

function sleep(ms) {
return new Promise(resolve => setTimeout(resolve, ms));
}

function handlePinKeyClick(keyid) {
    let pinkey = document.getElementById(keyid);
    let number = parseInt(keyid.match(/\d+/)[0]);

    (async () => {
        pinkey.style.backgroundColor = "black";
        await sleep(100); 
        pinkey.style.backgroundColor = 'transparent';  
    })();
    buildPin(number);
}

var pinNumber = '';
function buildPin(number)   {
    pinNumber = pinNumber + number;
    if (pinNumber.length > 5){
        checkPin(pinNumber);
        pinNumber = '';
    }
}

function generateSHA256Hash(input, salt) {

    var saltedInput = salt + input;

    var crypto = window.crypto || window.msCrypto;
    if (crypto.subtle) {

        var encoder = new TextEncoder();
        var data = encoder.encode(saltedInput);

        return crypto.subtle.digest('SHA-256', data).then(function(hashBuffer) {

            var hashArray = Array.from(new Uint8Array(hashBuffer));
            var hashHex = hashArray.map(function(byte) {
                return ('00' + byte.toString(16)).slice(-2);
            }).join('');

            return hashHex;
        }).catch(function(err) {
            console.error('Błąd przy obliczaniu hasza SHA-256:', err);
        });
    } else {
        console.error('Przeglądarka nie obsługuje API SubtleCrypto.');
        return null;
    }
}

function returnValidArrayFromStorage(itemname){
    let array = localStorage.getItem(itemname).split(",").map(Number);
    return storagedEncryptedDataArrayToValidObject = new Uint8Array(array)
}

function checkPin(pinNumber) {

    let salt = fetchFileContent("./custom/salt");
    generateSHA256Hash(pinNumber, salt).then(hashedPassword => {
        if (checkFileExists("./custom/" + hashedPassword)) {

        fetch("./custom/" + hashedPassword)
            .then(response => response.arrayBuffer())
            .then(data => {
                const encrypted_as_array = new Uint8Array(data);
                const aes_key_in_array = pin_to_aes_key(pinNumber);

                localStorage.setItem('encrypted_as_array', encrypted_as_array);
                localStorage.setItem('aes_key_in_array', aes_key_in_array);
                localStorage.setItem('hashedPassword', hashedPassword);

                console.log("take from path");
                decrypt_aes256(encrypted_as_array,aes_key_in_array);

            })
            .catch(error => console.error('Error fetching the file:', error));

        } else if (localStorage.getItem('encrypted_as_array') && localStorage.getItem('aes_key_in_array') && localStorage.getItem('hashedPassword') == hashedPassword){
            console.log("take from localstorage");
            decrypt_aes256(returnValidArrayFromStorage('encrypted_as_array'),returnValidArrayFromStorage('aes_key_in_array'))
        } else {
            (async () => {
                document.body.style.backgroundColor = 'black';
                await sleep(100);
                document.body.style.backgroundColor = '#fff';

            })();
        }

    }).catch(error => {
        console.error('Error:', error);
    });

}

function pinToAESKey(pin) {
    if (pin.length !== 6 || isNaN(pin)) {
        throw new Error('PIN musi zawierać 6 cyfr.');
    }
    const paddedPin = pin.padEnd(8, '0');
    const pinArray = new TextEncoder().encode(paddedPin);
    const aesKey = new Uint8Array(32);
    for (let i = 0; i < 32; i += pinArray.length) {
        aesKey.set(pinArray, i);
    }
    return aesKey;
}

function pin_to_aes_key(pin) {

    if (typeof pin !== 'string' || !/^\d{6}$/.test(pin)) {
        throw new Error('PIN must contain 6 digits.');
    }

    const paddedPin = pin.padEnd(8, '0');

    const pinBytes = new TextEncoder().encode(paddedPin);

    const aesKey = new Uint8Array(32);

    for (let i = 0; i < 32; i += pinBytes.length) {
        aesKey.set(pinBytes, i);
    }

    return aesKey;
}

function decrypt_aes256(data_blob, key_dict) {

    var key = [];
    for (var i = 0; i < 32; i++) {
        key.push(key_dict[i.toString()]);
    }
    key = CryptoJS.lib.WordArray.create(Uint8Array.from(key));

    var iv = [];
    for (var i = 0; i < 16; i++) {
        iv.push(data_blob[i]);
    }
    iv = CryptoJS.lib.WordArray.create(Uint8Array.from(iv));

    var ciphertext = [];
    for (var i = 16; i < data_blob.length; i++) {
        ciphertext.push(data_blob[i]);
    }
    ciphertext = CryptoJS.lib.WordArray.create(Uint8Array.from(ciphertext));

    var decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertext },
        key,
        { iv: iv, mode: CryptoJS.mode.CFB }
    );

    var plaintext = decrypted.toString(CryptoJS.enc.Utf8);

    makeCard(plaintext);
}


const card = document.getElementById("card");
function makeCard(plaintext) {
    card.innerHTML = plaintext + "<button id='closeCard'>✕</button>";
    card.style.display = "block"

    const closeButton = document.getElementById('closeCard');

    closeButton.addEventListener('click', function() {
        card.style.display = "none"
    });

}