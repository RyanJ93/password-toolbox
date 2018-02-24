const passwordToolBox = require('password-toolbox');

//Generating a password.
var password = passwordToolBox.generator.generate(12);
console.log('Random password: ' + password);

//Generating a human readable password.
passwordToolBox.generator.setDictionaryPath(__dirname + '/dictionary.txt').generateHumanReadable(12, 2).then(function(psw){
	console.log('Human readable password: ' + psw);
}).catch(function(error){
	console.log(error);
});

//Analyzing password.
var analysis = passwordToolBox.analyzer.analyze(password);
console.log(analysis);

//Complete password analysis.
passwordToolBox.analyzer.setDictionaryPath(__dirname + '/rockyou.txt').completeAnalysis(password).then(function(analysis){
	console.log(analysis);
}).catch(function(error){
	console.log(error);
});

//Creating a hash from the password.
var hash = passwordToolBox.hash.createSimpleHash(password);
console.log(hash);

//Comparing the created hash with the original password.
var result = passwordToolBox.hash.compareSimpleHash(password, hash);
console.log(result);

//Creating a more complex hash.
hash = passwordToolBox.hash.createHash(password);
console.log(hash);

//Comparing the new hash with the original password.
result = passwordToolBox.hash.compareHash(password, hash);
console.log(result);