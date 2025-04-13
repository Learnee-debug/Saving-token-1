const jwt = require('jsonwebtoken');
const crypto = require('crypto');


const secretKey = crypto.randomBytes(32).toString('hex');


const encrypt = (payload) => {
  try {

    const token = jwt.sign(payload, secretKey, { algorithm: 'HS256', expiresIn: '1h' });
    return token;
  } catch (error) {
    console.error('Error during encryption:', error);
    throw error;
  }
};


const decrypt = (token) => {
  try {

    const decoded = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
    return decoded;
  } catch (error) {
    console.error('Error during decryption:', error);
    throw error;
  }
};


const checkEncryptionDecryption = () => {
  try {

    const payload = {
      userId: 123,
      username: 'john_doe'
    };

    const token = encrypt(payload);
    console.log('Encrypted Token:', token);


    const decodedPayload = decrypt(token);
    console.log('Decoded Payload:', decodedPayload);

    // Check if the original payload matches the decoded payload
    if (JSON.stringify(payload) === JSON.stringify(decodedPayload)) {
      console.log('Success');
    } else {
      console.log('Failure');
    }
  } catch (error) {
    console.error('Error during check:', error);
  }
};

// Run the check function to verify the implementation
checkEncryptionDecryption();

module.exports = {
  encrypt,
  decrypt
};