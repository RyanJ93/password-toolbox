const filesystem = require('fs');
const crypto = require('crypto');

var passwordToolBox = {
	analyzer: {
		/**
		* @var String dictionary A string containing the path to the dictionary file that contains a list of weak passwords separated by a breakline (\n).
		*/
		dictionary: null,
		
		/**
		* @var String wordlist A string containing the content of the dictionary, if it is going to be cached for next uses.
		*/
		wordlist: null,
		
		/**
		* @var Boolean cache If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		cache: false,
		
		/**
		* @var Boolean ci If set to "true", the passwords will be analyzed in case-insensitive way, otherwise not.
		*/
		ci: true,
		
		/**
		* Sets the path to the dictionary file, this method is chainable.
		*
		* @param String path A string containing the path to the dictionary.
		*
		* @throws exception If an invalid dictionary path is provided. 
		*/
		setDictionaryPath: function(path){
			if ( typeof(path) !== 'string' ){
				throw 'Invalid path.';
			}
			if ( path === '' ){
				path = null;
			}
			if ( this.dictionary !== path ){
				this.wordlist = this.cache === false ? null : '';
				this.dictionary = path;
			}
			return this;
		},
		
		/**
		* Returns the path to the dictionary.
		*
		* @return String A string containing the path to the dictionary.
		*/
		getDictionaryPath: function(){
			return this.dictionary === '' || typeof(this.dictionary) !== 'string' ? null : this.dictionary;
		},
		
		/**
		* Sets if the dictionary cache shall be used or not, this method is chainable.
		*
		* @param Boolean value If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		setDictionaryCache: function(value){
			if ( value !== true ){
				this.cache = false;
				this.wordlist = null;
				return this;
			}
			this.cache = true;
			return this;
		},
		
		/**
		* Returns if the dictionary cache is enabled or not.
		*
		* @return Boolean If the dictionary cache is enabled will be returned "true", otherwise "false".
		*/
		getDictionaryCache: function(){
			return this.cache === false ? false : true;
		},
		
		/**
		* Cleares the content of the dictionary cache, this method is chainable.
		*/
		invalidateDictionaryCache: function(){
			this.wordlist = null;
			return this;
		},
		
		/**
		* Sets if the passwords shall be analyzed in case-insensitive way or not, this method is chainable.
		*
		* @param Boolean value If set to "true" the passwords will be analyzed in case-insensitive way, otherwise not.
		*/
		setCaseInsensitive: function(value){
			this.ci = value === false ? false : true;
			return this;
		},
		
		/**
		* Returns if the passwords shall be analyzed in case-insensitive way or not.
		*
		* @return boolean If the passwords will be analyzed in case-insensitive way will be returned "true", otherwise "false".
		*/
		getCaseInsensitive: function(){
			return this.ci === true ? true : false;
		},
		
		/**
		* Analyzes a given password.
		*
		* @param String password The password to analyze.
		* @param Array keywords An optional sequeantial array of strings containing some keywords which shall be looked into the given password (like first name, surname, e-mail address and so on).
		*
		* @return Object An object containing the information of the analysis, like chars counts, keywords counts and strength score.
		*/
		analyze: function(password, keywords){
			let analysis = {
				numbers: 0,
				uppercaseLetters: 0,
				lowercaseLetters: 0,
				specialChars: 0,
				length: 0,
				keywords: {},
				keywordsCount: 0,
				keywordsUniqueCount: 0,
				score: 0
			};
			if ( typeof(password) !== 'string' || password === '' ){
				return analysis;
			}
			analysis.length = password.length;
			analysis.numbers = password.match(/[0-9]/g);
			analysis.numbers = analysis.numbers === null ? 0 : analysis.numbers.length;
			analysis.uppercaseLetters = password.match(/[A-Z]/g);
			analysis.uppercaseLetters = analysis.uppercaseLetters === null ? 0 : analysis.uppercaseLetters.length;
			analysis.lowercaseLetters = password.match(/[a-z]/g);
			analysis.lowercaseLetters = analysis.lowercaseLetters === null ? 0 : analysis.lowercaseLetters.length;
			analysis.specialChars = password.match(/[^A-Za-z0-9]/g);
			analysis.specialChars = analysis.specialChars === null ? 0 : analysis.specialChars.length;
			if ( this.ci !== false ){
				password = password.toLowerCase();
			}
			analysis.score = password.length < 15 ? - ( Math.floor( ( ( 15 - password.length ) * 100 ) / 15 ) ) : 0;
			if ( analysis.numbers === 0 ){
				analysis.score -= 10;
			}
			if ( analysis.uppercaseLetters === 0 ){
				analysis.score -= 10;
			}
			if ( analysis.lowercaseLetters === 0 ){
				analysis.score -= 10;
			}
			if ( analysis.specialChars === 0 ){
				analysis.score -= 5;
			}
			let chars = new Array();
			for ( let i = 0 ; i < password.length ; i++ ){
				let letter = password.charAt(i);
				if ( typeof(chars[letter]) !== 'undefined' ){
					chars[letter]++;
				}else{
					chars[letter] = 0;
				}
			}
			for ( let letter in chars ){
				if ( chars[letter] !== 0 ){
					analysis.score -= Math.floor(( ( chars[letter] * 100 ) / password.length ) / 5);
				}
			}
			if ( Array.isArray(keywords) === true && keywords.length > 0 ){
				for ( let i = 0 ; i < keywords.length ; i++ ){
					if ( typeof(keywords[i]) !== 'string' || keywords[i] === '' ){
						continue;
					}
					if ( this.ci !== false ){
						keywords[i] = keywords[i].toLowerCase();
					}
					let buffer = password.split(keywords[i]).length - 1;
					analysis.keywords[keywords[i]] = buffer;
					if ( buffer !== 0 ){
						analysis.keywordsCount += buffer;
						analysis.keywordsUniqueCount++;
						analysis.score -= buffer * 5;
					}
				}
			}
			analysis.score = 100 + analysis.score;
			analysis.score = analysis.score > 100 ? 100 : ( analysis.score < 0 ? 0 : analysis.score );
			return analysis;
		},
		
		/**
		* Analyzes a given password using also a dictionary of weak passwords to test its strength.
		*
		* @param String password The password to analyze.
		* @param Array info A sequential array of strings containing some additional information which shall be looked into the given password (like first name, surname, e-mail address and so on).
		*/
		completeAnalysis: function(password, keywords){
			return new Promise(function(resolve, reject){
				let analysis = passwordToolBox.analyzer.analyze(password, keywords);
				if ( typeof(passwordToolBox.analyzer.dictionary) !== 'string' || passwordToolBox.analyzer.dictionary === '' ){
					return resolve(analysis);
				}
				if ( passwordToolBox.analyzer.ci !== false ){
					password = password.toLowerCase();
				}
				if ( passwordToolBox.analyzer.cache === true && typeof(passwordToolBox.analyzer.wordlist) === 'string' ){
					if ( passwordToolBox.analyzer.wordlist.indexOf(password + '\n') >= 0 ){
						analysis.score -= analysis.score > 50 ? 25 : 10;
					}
					analysis.score = analysis.score > 100 ? 100 : ( analysis.score < 0 ? 0 : analysis.score );
					return resolve(analysis);
				}else if ( passwordToolBox.analyzer.cache === true && ( typeof(passwordToolBox.analyzer.wordlist) !== 'string' || passwordToolBox.analyzer.wordlist === '' ) ){
					try{
						let data = filesystem.readFileSync(__dirname + '/' + passwordToolBox.analyzer.dictionary).toString();
						if ( data === '' ){
							return resolve(analysis);
						}
						passwordToolBox.analyzer.wordlist = data;
						if ( data.indexOf(password + '\n') >= 0 ){
							analysis.score -= analysis.score > 50 ? 25 : 10;
						}
						analysis.score = analysis.score > 100 ? 100 : ( analysis.score < 0 ? 0 : analysis.score );
						return resolve(analysis);
					}catch(ex){
						console.log(ex);
						return reject();
					}
				}
				try{
					let stream = filesystem.createReadStream(__dirname + '/' + passwordToolBox.analyzer.dictionary, 'utf8');
					let buffer = '';
					stream.on('data', function(chunk){
						if ( chunk.charAt(chunk.length - 1) !== '\n' ){
							let index = chunk.lastIndexOf('\n');
							buffer = chunk.substr(index + 1);
							chunk = chunk.substr(0, index);
						}
						if ( buffer !== '' ){
							chunk = buffer + chunk;
							buffer = '';
						}
						if ( chunk.indexOf(password + '\n') >= 0 ){
							analysis.score -= analysis.score > 50 ? 25 : 10;
							stream.destroy();
						}
					}).on('end', function(){
						analysis.score = analysis.score > 100 ? 100 : ( analysis.score < 0 ? 0 : analysis.score );
						resolve(analysis);
					}).on('close', function(){
						analysis.score = analysis.score > 100 ? 100 : ( analysis.score < 0 ? 0 : analysis.score );
						resolve(analysis);
					}).on('error', function(){
						return reject();
					});
				}catch(ex){
					console.log(ex);
					return reject();
				}
			});
		}
	},
	
	generator: {
		/**
		* @var String dictionary A string containing the path to the dictionary file that contains a list of words separated by a breakline (\n).
		*/
		dictionary: null,
		
		/**
		* @var String wordlist A string containing the content of the dictionary, if it is going to be cached for next uses.
		*/
		wordlist: null,
		
		/**
		* @var Boolean cache If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		cache: false,
		
		/**
		* Sets the path to the dictionary file, this method is chainable.
		*
		* @param String path A string containing the path to the dictionary.
		*
		* @throws exception If an invalid dictionary path is provided. 
		*/
		setDictionaryPath: function(path){
			if ( typeof(path) !== 'string' ){
				throw 'Invalid path.';
			}
			if ( path === '' ){
				path = null;
			}
			if ( this.dictionary !== path ){
				this.wordlist = this.cache === false ? null : '';
				this.dictionary = path;
			}
			return this;
		},
		
		/**
		* Returns the path to the dictionary.
		*
		* @return String A string containing the path to the dictionary.
		*/
		getDictionary: function(){
			return this.dictionary === '' || typeof(this.dictionary) !== 'string' ? null : this.dictionary;
		},
		
		/**
		* Sets if the dictionary cache shall be used or not, this method is chainable.
		*
		* @param Boolean value If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		setDictionaryCache: function(value){
			if ( value !== true ){
				this.cache = false;
				this.wordlist = null;
				return this;
			}
			this.cache = true;
			return this;
		},
		
		/**
		* Returns if the dictionary cache is enabled or not.
		*
		* @return Boolean If the dictionary cache is enabled will be returned "true", otherwise "false".
		*/
		getDictionaryCache: function(){
			return this.cache === true ? true : false;
		},
		
		/**
		* Cleares the content of the dictionary cache, this method is chainable.
		*/
		invalidateDictionaryCache: function(){
			this.wordlist = null;
			return this;
		},
		
		/**
		* Generate a random password long as much as specified.
		*
		* @param Integer length An integer number greater than zero representing the password length.
		* @param String pattern A string containing all possible chars that the password can contain, if not specified, the generated password may contain both letters (a-Z) and numbers.
		*
		* @return String A string containing the generated password.
		*/
		generate: function(length, pattern){
			if ( isNaN(length) === true || length <= 0 ){
				return '';
			}
			return passwordToolBox.hash.generateRandomToken(length, pattern);
		},
		
		/**
		* Generate a random password using a given dictionary.
		*
		* @param Integer length An integer number greater than zero representing the password length.
		* @param Integer numLength An integer number greater or equal than zero representing the length of an additional numeric string added to the password, if set to 0 or not set no additional string will be generated.
		* @param Integer chunkSize The size (in chars) of the portion that will be read from the dictionary while looking for a random word, by default is set to 4096.
		*
		* @return String A string containing the generated password.
		*/
		generateHumanReadable: function(length, numLength, chunkSize){
			return new Promise(function(resolve, reject){
				if ( isNaN(length) === true || length <= 0 ){
					return reject();
				}
				let path = passwordToolBox.generator.dictionary;
				if ( typeof(path) !== 'string' || path === '' ){
					return reject();
				}
				numLength = numLength <= 0 || isNaN(numLength) === true ? 0 : Math.floor(numLength);
				let number = '';
				if ( numLength !== 0 ){
					if ( numLength > length ){
						length = numLength;
					}
					number = passwordToolBox.hash.generateRandomToken(numLength, '0123456789');
					if ( numLength === length ){
						return resolve(number);
					}
					length = length - numLength;
				}
				let dictionary = '';
				let password = '';
				chunkSize = chunkSize <= 1 || isNaN(chunkSize) === true ? 4096 : ( chunkSize > Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : chunkSize );
				if ( passwordToolBox.generator.cache === true && typeof(passwordToolBox.generator.wordlist) === 'string' ){
					dictionary = passwordToolBox.generator.wordlist;
					if ( dictionary === '' ){
						return resolve('');
					}
					dictionary = dictionary.substr(0, Number.MAX_SAFE_INTEGER);
					while ( password === '' ){
						let portion = passwordToolBox.hash.generateRandomNumber(0, dictionary.length - chunkSize);
						portion = dictionary.substr(portion, chunkSize);
						if ( portion.charAt(portion.length - 1) !== '\n' ){
							portion = portion.substr(0, portion.lastIndexOf('\n'));
						}
						if ( portion === '' ){
							continue;
						}
						portion = portion.split('\n');
						while ( password === '' ){
							let buffer = portion[passwordToolBox.hash.generateRandomNumber(0, portion.length)];
							if ( buffer.length === length ){
								password = buffer;
								break;
							}
						}
					}
					return resolve(passwordToolBox.hash.generateRandomNumber(0, 1) === 1 ? password + number : number + password);
				}
				try{
					dictionary = filesystem.readFileSync(__dirname + '/' + path).toString();
					if ( dictionary === '' ){
						return resolve('');
					}
					dictionary = dictionary.substr(0, Number.MAX_SAFE_INTEGER);
					if ( passwordToolBox.generator.cache === true ){
						passwordToolBox.generator.wordlist = dictionary;
					}
					while ( password === '' ){
						let portion = passwordToolBox.hash.generateRandomNumber(0, dictionary.length - chunkSize);
						portion = dictionary.substr(portion, chunkSize);
						if ( portion.charAt(portion.length - 1) !== '\n' ){
							portion = portion.substr(0, portion.lastIndexOf('\n'));
						}
						if ( portion === '' ){
							continue;
						}
						portion = portion.split('\n');
						while ( password === '' ){
							let buffer = portion[passwordToolBox.hash.generateRandomNumber(0, portion.length)];
							if ( buffer.length === length ){
								password = buffer;
								break;
							}
						}
					}
					resolve(passwordToolBox.hash.generateRandomNumber(0, 1) === 1 ? password + number : number + password);
				}catch(ex){
					console.log(ex);
					return reject();
				}
			});
		}
	},
	
	hash: {
		/**
		* Generate a random string.
		*
		* @param Integer length An integer number greater than zero representing the string length.
		* @param String pattern A string containing all the chars that can be used in the random string.
		*
		* @return String The generated string.
		*/
		generateRandomToken: function(length, pattern){
			if ( isNaN(length) === true || length <= 0 ){
				return '';
			}
			length = Math.floor(length);
			if ( typeof(pattern) !== 'string' || pattern === '' ){
				pattern = 'abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789';
			}
			let buffer = crypto.randomBytes(length);
			let value = new Array(length);
			for ( let i = 0 ; i < length ; i++ ){
				value[i] = pattern[buffer[i] % pattern.length];
			}
			return value.join('');
		},
		
		/**
		* Generate a random number.
		*
		* @param Number min The minimum number that can be generated.
		* @param Number max The maximum number that can be generated.
		*
		* @return Number The generated number.
		*
		* @throws exception If the difference between minimum and maximum value is greater than the supported limit.
		* @throws exception If the maximum value provided is greater than the supported one.
		*/
		generateRandomNumber: function(min, max){
			let distance = max - min;
			if ( min >= max ){
				max = min + 1;
			}
			if ( distance > 281474976710655 ){
				throw 'You cannot get all possible random numbers if range is greater than 256^6-1.';
			}
			if ( max > Number.MAX_SAFE_INTEGER ){
				throw 'Maximum number should be safe integer limit.';
			}
			let bytes = 6;
			let dec = 281474976710656;
			if ( distance < 256 ){
				bytes = 1;
				dec = 256;
			}else if ( distance < 65536 ){
				bytes = 2;
				dec = 65536;
			}else if ( distance < 16777216 ){
				bytes = 3;
				dec = 16777216;
			}else if ( distance < 4294967296 ){
				bytes = 4;
				dec = 4294967296;
			} else if ( distance < 1099511627776 ){
				maxBytes = 5;
				maxDec = 1099511627776;
			}
			let result = Math.floor(parseInt(crypto.randomBytes(bytes).toString('hex'), 16) / dec * ( max - min + 1 ) + min);
			if ( result > max ){
				result = max;
			}
			return result;
		},
		
		/**
		* Creates an hash from the given password.
		*
		* @param String password A string containing the password.
		* @param String algorithm A string cotnaining the algorithm name, is not set, "sha512" will be used.
		*
		* @return String The hashed password.
		*
		* @throws exception If the given password is invalid.
		* @throws exception If the given algorithm name is not supported.
		*/
		createSimpleHash: function(password, algorithm){
			if ( typeof(password) !== 'string' || password === '' ){
				throw 'Invalid password.';
			}
			if ( typeof(algorithm) !== 'string' || algorithm === '' ){
				algorithm = 'sha512';
			}
			try{
				return crypto.createHash(algorithm).update(password).digest('hex');
			}catch(ex){
				console.log(ex);
				throw 'Invalid algorithm';
			}
		},
		
		/**
		* Creates a more sophisticated hash using the given password.
		*
		* @param String password A string containing the password.
		* @param Object options An object containing the additional options for the algorithm.
		*
		* @return Object An object containing the hashed password and the respective parameters.
		*
		* @throws exception If the given password is invalid.
		* @throws exception If the given algorithm name is not supported.
		*/
		createHash: function(password, options){
			if ( typeof(password) !== 'string' || password === '' ){
				throw 'Invalid password.';
			}
			if ( typeof(options) !== 'object' || options === null ){
				options = {};
			}
			let algorithm = typeof(options.algorithm) !== 'string' || options.algorithm === '' ? 'sha512' : options.algorithm;
			let min = typeof(options.minLoopValue) === 'undefined' || isNaN(options.minLoopValue) === true || options.minLoopValue <= 1 ? 1 : Math.floor(options.minLoopValue);
			let max = typeof(options.maxLoopValue) === 'undefined' || isNaN(options.maxLoopValue) === true ? 256 : Math.floor(options.maxLoopValue);
			if ( min > max ){
				max = min + 1;
			}
			let loop = typeof(options.randomLoop) !== 'undefined' && options.randomLoop === false ? 1 : this.generateRandomNumber(min, max);
			let value = 32;
			if ( typeof(options.saltLength) !== 'undefined' && isNaN(options.saltLength) === false ){
				value = Math.floor(options.saltLength);
				value = value <= 1 ? 1 : ( value > 256 ? 256 : value );
			}
			let salt = typeof(options.useSalt) !== 'undefined' && options.useSalt === false ? '' : this.generateRandomToken(value);
			value = 32;
			if ( typeof(options.pepperLength) !== 'undefined' && isNaN(options.pepperLength) === false ){
				value = Math.floor(options.pepperLength);
				value = value <= 1 ? 1 : ( value > 256 ? 256 : value );
			}
			let pepper = typeof(options.usePepper) !== 'undefined' && options.usePepper === false ? '' : this.generateRandomToken(value);
			password = salt + password + pepper;
			try{
				for ( let i = 0 ; i < loop ; i++ ){
					password = crypto.createHash(algorithm).update(password).digest('hex');
				}
			}catch(ex){
				console.log(ex);
				throw 'Invalid algorithm';
			}
			return {
				salt: salt,
				pepper: pepper,
				loop: loop,
				password: password,
				algorithm: algorithm
			};
		},
		
		/**
		* Checks if a given password corresponds with the given hash.
		*
		* @param String password A string containing the password.
		* @param String hash The hashed password that shall be compared.
		* @param String algorithm A string containing the name of the algorithm that has been used to hash the original password, if not set "sha512" will be used.
		*
		* @return Boolean If the given password corresponds will be returned "true", otherwise "false".
		*
		* @throws exception If the given algorithm name is not supported.
		*/
		compareSimpleHash: function(password, hash, algorithm){
			if ( typeof(password) !== 'string' || password === '' ){
				return false;
			}
			if ( typeof(hash) !== 'string' || hash === '' ){
				return false;
			}
			try{
				return crypto.timingSafeEqual(new Buffer(this.createSimpleHash(password, algorithm)), new Buffer(hash)) === true ? true : false;
			}catch(ex){
				throw 'Invalid algorithm';
			}
		},
		
		/**
		* Checks if a given password corresponds with the given hash as object.
		*
		* @param String password A string containing the password.
		* @param Object hash An object containing the password hash and the respective parameters.
		*
		* @return Boolean If the given password corresponds will be returned "true", otherwise "false".
		*
		* @throws exception If the given algorithm name is not supported.
		*/
		compareHash: function(password, hash){
			if ( typeof(password) !== 'string' || password === '' ){
				return false;
			}
			if ( typeof(hash) !== 'object' || hash === null || typeof(hash.password) !== 'string' || hash.password === '' ){
				return false;
			}
			let algorithm = typeof(hash.algorithm) !== 'string' || hash.algorithm === '' ? 'sha512' : hash.algorithm;
			let loop = typeof(hash.loop) !== 'number' || hash.loop <= 1 ? 1 : Math.floor(hash.loop);
			let salt = typeof(hash.salt) !== 'string' ? '' : hash.salt;
			let pepper = typeof(hash.pepper) !== 'string' ? '' : hash.pepper;
			password = salt + password + pepper;
			try{
				for ( let i = 0 ; i < loop ; i++ ){
					password = crypto.createHash(algorithm).update(password).digest('hex');
				}
				return crypto.timingSafeEqual(new Buffer(password), new Buffer(hash.password)) === true ? true : false;
			}catch(ex){
				console.log(ex);
				throw 'Invalid algorithm';
			}
		}
	}
};

exports.analyzer = passwordToolBox.analyzer;
exports.generator = passwordToolBox.generator;
exports.hash = passwordToolBox.hash;