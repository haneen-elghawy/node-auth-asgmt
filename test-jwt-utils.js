const { signJWT, verifyJWT } = require('./jwt-utils');

const secret = 'mySuperSecretKey';
const payload = {
  userId: 123,
  username: 'testuser',
};


const token = signJWT(payload, secret, 10); 
console.log('Generated JWT:', token);

try {
  const decoded = verifyJWT(token, secret);
  console.log('Verified payload:', decoded);
} catch (err) {
  console.error('Verification failed:', err.message);
}


try {
  const tampered = token.replace('a', 'b'); 
  verifyJWT(tampered, secret);
  console.log('Tampered token passed (unexpected!)');
} catch (err) {
  console.error('Tampered token detected:', err.message);
}
