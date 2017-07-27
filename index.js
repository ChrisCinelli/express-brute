var _ = require('underscore');
var crypto = require('crypto');

var ExpressBrute = module.exports = function (store, options) {
	var i;
	
	_.bindAll(this, 'reset', 'whitelist', 'blacklist', 'status', 'getMiddleware');

	// set options
	this.options = _.extend({}, ExpressBrute.defaults, options);
	ExpressBrute.instanceCount++;
	this.name = this.options.name || ("brute" + ExpressBrute.instanceCount);
	ExpressBrute.instances[this.name] = this;
	
	if (this.options.minWait < 1) {
		this.options.minWait = 1;
	}
	this.store = store;

	// build delays array
	this.delays = [this.options.minWait];
	while(this.delays[this.delays.length-1] < this.options.maxWait) {
		var nextNum = this.delays[this.delays.length-1] + (this.delays.length > 1 ? this.delays[this.delays.length-2] : 0);
		this.delays.push(nextNum);
	}
	this.delays[this.delays.length-1] = this.options.maxWait;

	// set default lifetime
	if (typeof this.options.lifetime == "undefined") {
		this.options.lifetime = (this.options.maxWait/1000)*(this.delays.length + this.options.freeRetries);
		this.options.lifetime = Math.ceil(this.options.lifetime);
	}

	// generate "prevent" middleware
	this.prevent = this.getMiddleware();
};

expressBruteRequestObject = {};
// Call all the instances
['whitelist', 'blacklist', 'status'].map(function(funcName){
	expressBruteRequestObject[funcName] = function() {
		for (var i in ExpressBrute.instances) {
			ExpressBrute.instances[i][funcName].apply(ExpressBrute.instances[i], arguments);
		}
	}
});

ExpressBrute.prototype.getMiddleware = function (options) {
	// standardize input
	options = _.extend({}, options);
	var keyFunc = options.key;
	if (typeof keyFunc !== 'function') {
		keyFunc = function (req, res, next) { next(options.key); };
	}
	var getFailCallback = _.bind(function () {
		return typeof options.failCallback === 'undefined' ? this.options.failCallback : options.failCallback;
	}, this);

	// create middleware
	return _.bind(function (req, res, next) {
		var ip = req.ip;
		keyFunc(req, res, _.bind(function (key) {
			var storeKey = this.getKey(!options.ignoreIP && ip, key);
		
			// Expose functions
			req.brute = req.brute || _.extend({ instances: ExpressBrute.instances }, expressBruteRequestObject);

			// attach a simpler "reset" function to req.brute.reset
			if (this.options.attachResetToRequest) {
				var reset = _.bind(function (callback) {
					this.store.reset(storeKey, function (err) {
						if (typeof callback == 'function') {
							process.nextTick(function () {
								callback(err);
							});
						}
					});
				}, this);
				if (req.brute && req.brute.reset) {
					// wrap existing reset if one exists
					var oldReset = req.brute.reset;
					var newReset = reset;
					reset = function (callback) {
						oldReset(function () {
							newReset(callback);
						});
					};
				}
				
				req.brute.reset = reset;
			}


			// filter request
			this.store.get(storeKey, _.bind(function (err, value) {
				if (err) {
					this.options.handleStoreError({
						req: req,
						res: res,
						next: next,
						message: "Cannot get request count",
						parent: err
					});
					return;
				}

				var count = 0,
					delay = 0,
					lastValidRequestTime = this.now(),
					firstRequestTime = lastValidRequestTime;
				if (value) {
					if (value.wl) {
						typeof next == 'function' && next();
						return;
					}
					
					if (value.bl) {
						var failCallback = getFailCallback();
						typeof failCallback === 'function' && failCallback(req, res, next, -1);
						return;
					}
					
					count = value.count;
					lastValidRequestTime = value.lastRequest.getTime();
					firstRequestTime = value.firstRequest.getTime();

					var delayIndex = value.count - this.options.freeRetries - 1;
					if (delayIndex >= 0) {
						if (delayIndex < this.delays.length) {
							delay = this.delays[delayIndex];
						} else {
							delay = this.options.maxWait;
						}
					}
				}
				var nextValidRequestTime = lastValidRequestTime+delay,
					remainingLifetime = this.options.lifetime || 0;

				if (!this.options.refreshTimeoutOnRequest && remainingLifetime > 0) {
					remainingLifetime = remainingLifetime - Math.floor((this.now() - firstRequestTime) / 1000);
					if (remainingLifetime < 1) {
						// it should be expired alredy, treat this as a new request and reset everything
						count = 0;
						delay = 0;
						nextValidRequestTime = firstRequestTime = lastValidRequestTime = this.now();
						remainingLifetime = this.options.lifetime || 0;
					}
				}

				if (nextValidRequestTime <= this.now() || count <= this.options.freeRetries) {
					var valueToStore = {
						count: count+1,
						lastRequest: new Date(this.now()),
						firstRequest: new Date(firstRequestTime)
					}; 
					if (this.options.storeIp) {
						valueToStore.ip = ip;
					}
					if (this.options.storeKey) {
						valueToStore.key = key;
					}
					
					this.store.set(storeKey, valueToStore, remainingLifetime, _.bind(function (err) {
						if (err) {
							this.options.handleStoreError({
								req: req,
								res: res,
								next: next,
								message: "Cannot increment request count",
								parent: err
							});
							return;
						}
						typeof next == 'function' && next();
					},this));
				} else {
					var failCallback = getFailCallback();
					typeof failCallback === 'function' && failCallback(req, res, next, new Date(nextValidRequestTime));
				}
			}, this));
		},this));
	}, this);
};
ExpressBrute.prototype.reset = function (ip, key, callback) {
	var storeKey = this.getKey(ip, key);
	
	this.store.reset(storeKey, _.bind(function (err) {
		if (err) {
			this.options.handleStoreError({
				message: "Cannot reset request count",
				parent: err,
				key: key,
				storeKey: storeKey,
				ip: ip
			});
		} else {
			if (typeof callback == 'function') {
				process.nextTick(_.bind(function () {
					callback.apply(this, arguments);
				}, this));
			}
		}
	},this));
};

ExpressBrute.prototype.blacklist = function (ip, key, callback) {
	var storeKey = this.getKey(ip, key);

	var valueToStore = {
		bl: new Date(this.now()),
	};
	if (this.options.storeIp) {
		valueToStore.ip = ip;
	}
	if (this.options.storeKey) {
		valueToStore.key = key;
	}
	
	this.store.set(storeKey, valueToStore, 0, _.bind(function (err) {
		if (err) {
			this.options.handleStoreError({
				req: req,
				res: res,
				next: next,
				message: "Blacklist error",
				parent: err
			});
		} else {
			if (typeof callback == 'function') {
				process.nextTick(_.bind(function () {
					callback.apply(this, arguments);
				}, this));
			}
		}
	},this));
};

ExpressBrute.prototype.whitelist = function (ip, key, callback) {
	var storeKey = this.getKey(ip, key);

	var valueToStore = {
		wl: new Date(this.now()),
	};
	if (this.options.storeIp) {
		valueToStore.ip = ip;
	}
	if (this.options.storeKey) {
		valueToStore.key = key;
	}
	
	this.store.set(storeKey, valueToStore, 0, _.bind(function (err) {
		if (err) {
			this.options.handleStoreError({
				req: req,
				res: res,
				next: next,
				message: "Blacklist error",
				parent: err
			});
		} else {
			if (typeof callback == 'function') {
				process.nextTick(_.bind(function () {
					callback.apply(this, arguments);
				}, this));
			}
		}
	},this));
};
ExpressBrute.prototype.getBlAndWlKeys = function (callback) {
	if (!this.store.getBlAndWlKeys) return callback(new Error('This ExpressBrute store does not support getBlAndWlKeys'));
	if (!this.options.storeIp) return callback(new Error('In order to use getBlAndWlKeys, storeIp must be true'));
  this.store.getBlAndWlKeys(callback);
}
ExpressBrute.prototype.status = function (ip, key, callback) {
	var storeKey = this.getKey(ip, key);
	
	this.store.get(storeKey, _.bind(function (err, value) {
		if (err) {
			this.options.handleStoreError({
				req: req,
				res: res,
				next: next,
				message: "Cannot get request count",
				parent: err
			});
		} else {
			if (typeof callback == 'function') {
				process.nextTick(_.bind(function () {
					callback.call(this, { storeKey: storeKey, value: value});
				}, this));
			}
		}
	},this));
};


ExpressBrute.prototype.now = function () {
	return Date.now();
};

ExpressBrute.prototype.getKey = function (ip, key) {
	var ret;
	if(ip) {
		ret = this.options.storeHashKey([ip, this.name, key]);
		// console.log('getKey (', ip, this.name, key, ')', ret);

	} else {
		ret = this.options.storeHashKey([this.name, key]);
		// console.log('getKey (', this.name, key,	 ')', ret);

	}
	return ret;
}

var setRetryAfter = function (res, nextValidRequestDate) {
	var secondUntilNextRequest = nextValidRequestDate !== -1 ? Math.ceil((nextValidRequestDate.getTime() - Date.now())/1000) : 1000000000;
	res.header('Retry-After', secondUntilNextRequest);
};
ExpressBrute.FailTooManyRequests = function (req, res, next, nextValidRequestDate) {
	setRetryAfter(res, nextValidRequestDate);
	res.status(429);
	res.send({error: {text: "Too many requests in this time frame.", nextValidRequestDate: nextValidRequestDate}});
};
ExpressBrute.FailForbidden = function (req, res, next, nextValidRequestDate) {
	setRetryAfter(res, nextValidRequestDate);
	res.status(403);
	res.send({error: {text: "Too many requests in this time frame.", nextValidRequestDate: nextValidRequestDate}});
};
ExpressBrute.FailMark = function (req, res, next, nextValidRequestDate) {
	res.status(429);
	setRetryAfter(res, nextValidRequestDate);
	res.nextValidRequestDate = nextValidRequestDate;
	next();
};
ExpressBrute.FailSilently = function (req, res, next, nextValidRequestDate) {
	res.status(200);
	res.send({});
};

ExpressBrute._getKey = function (arr) {
	var hash = crypto.createHash('sha256');
	_(arr).each(function (part) {
		if (part) {
			hash.update(part);
		}
	});
	return hash.digest('base64');
};

ExpressBrute.MemoryStore = require('./lib/MemoryStore');
ExpressBrute.defaults = {
	freeRetries: 2,
	proxyDepth: 0,
	attachResetToRequest: true,
	refreshTimeoutOnRequest: true,
	minWait: 500,
	maxWait: 1000*60*15, // 15 minutes
	storeHashKey: ExpressBrute._getKey,
	storeIp: false,
	storeKey: false,
	failCallback: ExpressBrute.FailTooManyRequests,
	handleStoreError: function (err) {
		throw {
			message: err.message,
			parent: err.parent
		};
	}
};
ExpressBrute.instanceCount = 0;
ExpressBrute.instances = {};
