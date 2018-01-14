# Password toolkit

Password toolkit is a simple library that will help you handling passwords with Node.js without any dependencies.
You can use this library to generate suggested passwords, analyse user provided passwords in order to get a strength score and create a hash that can be stored within the database.

# Password analysis

Simple analysis:

`passwordToolBox.analyzer.analyze(password);`

Complete analysis (async with Promise support):

`passwordToolBox.analyzer.setDictionaryPath('rockyou.txt').completeAnalysis(password).then(function(analysis){}).catch(function(error){});`

Note that the complete analysis require a dictionary containing a list of weak passwords, passwords in this list must be separated by a break line (\n).
You can download dictionaries [here](https://wiki.skullsecurity.org/Passwords).
Both methods will return an object containing informations about chars count, keywords and the score.

# Password generation

Random password:

`passwordToolBox.generator.generate(12);`

Human readable password generation (async with Promise support):

`passwordToolBox.generator.setDictionaryPath('dictionary.txt').generateHumanReadable(12).then(function(password){}).catch(function(error){});`

Note that in order to generate human readable passwords you need a dictionary, words in the dictionary must be separated by a break line (\n).
If you are looking for an English word list, give a look [here](https://github.com/dwyl/english-words).

# Password hashing

Simple hash generation:

`passwordToolBox.hash.createSimpleHash(password);`

More complex hash generation:

`passwordToolBox.hash.createHash(password);`

The first method will return the hash as a string, the second one will return an object with the hash and its parameters (salts, algorithm, loop number).
If you need to compare a given password and a hash generated with the first method you can use this method:

`passwordToolBox.hash.compareSimpleHash(password, hash);`

While if you used the second method you can do this:

`passwordToolBox.hash.compareHash(password, hash);`

