const { hashPassword, verifyPassword } = require('./password-utils');

const password = 'SuperSecret123';


const storedHash = hashPassword(password);
console.log('Stored Hash:', storedHash);


const isCorrect = verifyPassword('SuperSecret123', storedHash);
console.log('Correct password check:', isCorrect); 


const isWrong = verifyPassword('WrongPassword', storedHash);
console.log('Incorrect password check:', isWrong); 
