var crypto        = require('crypto');
var assert        = require('assert');

var Benchmark     = require('benchmark');
var tweetnacl     = require('tweetnacl');
var tweetnaclfast = require('tweetnacl/nacl-fast');
var sodium        = require('sodium');
//var jsnacl        = require('js-nacl');

var base64_to_Uint8Array = function(input) {
  var raw = new Buffer(input, 'base64');
  var arr = new Uint8Array(new ArrayBuffer(raw.length));
  for(i = 0; i < raw.length; i++) {
    arr[i] = raw[i];
  }
  return arr;
};

var string_to_Uint8Array = function(str) {
  var raw = new Buffer(str, 'utf8');
  var arr = new Uint8Array(new ArrayBuffer(raw.length));
  for(i = 0; i < raw.length; i++) {
    arr[i] = raw[i];
  }
  return arr;
};

var _seed     = 'Aav6yqemxoPNNqxeKJXMlruKxXEHLD931S8pXzxt4mk=';
var _pubkey   = 'DsWygyoTcB7/NT5OqRzT0eaFf+6bJBSSBRfDOyU3x9k=';
var _message  = "Hi, this is a string that I want signed, will keep it short";
var _sig      = 'IvmJ8ntaMtcoVaU3lDToeQPdG/CdL7an4r013gYgJbY+eXJiwVZ9IxU/OC5htH41x2ezZRd83rTwe2+jf1f3CQ==';

/*********************** TweetNaCl tests ***************************/

var test_tweetnacl = function(nacl) {
  this.nacl     = nacl;
  this._seed    = base64_to_Uint8Array(_seed);
  this.key      = null;
  this._pubkey  = base64_to_Uint8Array(_pubkey);
  this._message = string_to_Uint8Array(_message);
  this.sig      = null;
  this._sig     = base64_to_Uint8Array(_sig);
};

test_tweetnacl.prototype.fromSeed = function() {
  this.key = this.nacl.sign.keyPair.fromSeed(this._seed);
};

test_tweetnacl.prototype.sign = function() {
  this.sig = this.nacl.sign.detached(this._message, this.key.secretKey);
};

test_tweetnacl.prototype.verify = function() {
  var r = this.nacl.sign.detached.verify(this._message, this.sig, this._pubkey);
  assert(r, "Verification failed!");
};

test_tweetnacl.prototype.validate = function() {
  assert(new Buffer(this.key.publicKey).toString('base64') === _pubkey, "wrong public key");
  assert(new Buffer(this.sig).toString('base64') === _sig, "wrong signature");
};

/*********************** Sodium tests **************************/

var test_sodium = function() {
  this._seed    = base64_to_Uint8Array(_seed);
  this.key      = null;
};

test_sodium.prototype.fromSeed = function() {
  this.key = new sodium.Key.Sign.fromSeed(_seed, 'base64');
};

test_sodium.prototype.sign = function() {
  // Detached signatures: https://github.com/paixaop/node-sodium/issues/22
  var signer = new sodium.Sign(this.key);
  var sig = signer.sign(_message, 'utf8');
  this.sig = sig.sign.slice(0, 64).toString('base64');
};

test_sodium.prototype.verify = function() {
  var input = {
    sign:         Buffer.concat([
      new Buffer(this.sig, 'base64'),
      new Buffer(_message, 'utf8')
    ]),
    publicKey:    new Buffer(_pubkey, 'base64')
  };
  var r = sodium.Sign.verify(input);
  assert(r, "Verification failed!");
};

test_sodium.prototype.validate = function() {
  assert(new Buffer(this.key.pk().get()).toString('base64') === _pubkey, "wrong public key");
  assert(this.sig === _sig, "wrong signature");
};

/*********************** js-NaCl tests ***************************

var test_jsnacl = function() {
  this.nacl     = jsnacl.instantiate();
  this._seed    = base64_to_Uint8Array(_seed);
  this.key      = null;
  this._pubkey  = base64_to_Uint8Array(_pubkey);
  this._message = string_to_Uint8Array(_message);
  this.sig      = null;
  this._sig     = base64_to_Uint8Array(_sig);
};

test_jsnacl.prototype.fromSeed = function() {
  this.key = this.nacl.crypto_sign_keypair_from_seed(this._seed);
};

test_jsnacl.prototype.sign = function() {
  this.sig = this.nacl.crypto_sign_detached(this._message, this.key.signSk);
};

test_jsnacl.prototype.verify = function() {
  var r = this.nacl.crypto_sign_verify_detached(this.sig, this._message, this.key.signPk);
  assert(r, "Verification failed!");
};

test_jsnacl.prototype.validate = function() {
  assert(new Buffer(this.key.signPk).toString('base64') === _pubkey, "wrong public key");
  assert(new Buffer(this.sig).toString('base64') === _sig, "wrong signature");
};


/*********************** Actual tests ***************************/
console.log("Correctness Testing:");

console.log(" - testing sodium");
var sod = new test_sodium();
sod.fromSeed();
sod.sign();
sod.verify();
sod.validate();

/*
console.log(" - testing js-NaCl");
var jsn = new test_jsnacl();
jsn.fromSeed();
jsn.sign();
jsn.verify();
jsn.validate();
*/
console.log(" - testing tweetnacl");
var tw1 = new test_tweetnacl(tweetnacl);
tw1.fromSeed();
tw1.sign();
tw1.verify();
tw1.validate();

console.log(" - testing tweetnacl-fast");
var tw2 = new test_tweetnacl(tweetnaclfast);
tw2.fromSeed();
tw2.sign();
tw2.verify();
tw2.validate();

/*********************** Benchmark HMAC-256 ***************************/
console.log("\nBrenchmark HMAC (from crypto):");

new Benchmark.Suite()
.add('HMAC-256 (crypto)', function() {
  crypto.createHmac('SHA256', _pubkey).update(_message).digest('base64');
})
.add('HMAC-512 (crypto)', function() {
  crypto.createHmac('SHA512', _pubkey).update(_message).digest('base64');
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
.run();


/*********************** Benchmark FromSeed ***************************/
console.log("\nBrenchmark FromSeed:");

new Benchmark.Suite()
.add('sodium.fromSeed', function() {
  sod.fromSeed();
})
/*.add('js-NaCl.fromSeed', function() {
  jsn.fromSeed();
})*/
.add('tweetnacl.fromSeed', function() {
  tw1.fromSeed();
})
.add('tweetnacl-fast.fromSeed', function() {
  tw2.fromSeed();
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
.on('complete', function() {
  console.log('Fastest is ' + this.filter('fastest').map('name'));
})
.run();

/*********************** Benchmark sign ***************************/
console.log("\nBrenchmark Sign:");

new Benchmark.Suite()
.add('sodium.sign', function() {
  sod.sign();
})
/*.add('js-NaCl.sign', function() {
  jsn.sign();
})*/
.add('tweetnacl.sign', function() {
  tw1.sign();
})
.add('tweetnacl-fast.sign', function() {
  tw2.sign();
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
.on('complete', function() {
  console.log('Fastest is ' + this.filter('fastest').map('name'));
})
.run();

/*********************** Benchmark verify ***************************/
console.log("\nBrenchmark Verify:");

new Benchmark.Suite()
.add('sodium.verify', function() {
  sod.verify();
})/*
.add('js-NaCl.verify', function() {
  jsn.verify();
})*/
.add('tweetnacl.verify', function() {
  tw1.verify();
})
.add('tweetnacl-fast.verify', function() {
  tw2.verify();
})
.on('cycle', function(event) {
  console.log(String(event.target));
})
.on('complete', function() {
  console.log('Fastest is ' + this.filter('fastest').map('name'));
})
.run();


console.log("\nDone");