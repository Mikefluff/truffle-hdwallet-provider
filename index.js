require("babel-polyfill");
var bip39 = require("bip39");
var hdkey = require('ethereumjs-wallet/hdkey');
var Wallet = require('ethereumjs-wallet');
var ProviderEngine = require("web3-provider-engine");
var TrezorSubprovider = require("trezor-wallet-provider");
var createLedgerSubprovider = require("@ledgerhq/web3-subprovider").default;
var FiltersSubprovider = require('web3-provider-engine/subproviders/filters.js');
var WalletSubprovider = require('web3-provider-engine/subproviders/wallet.js');
var Web3Subprovider = require("web3-provider-engine/subproviders/web3.js");
var NonceSubProvider = require('web3-provider-engine/subproviders/nonce-tracker.js');
var HookedSubprovider = require('web3-provider-engine/subproviders/hooked-wallet.js');
var ProviderSubprovider = require("web3-provider-engine/subproviders/provider.js");
var TransportU2F = require("@ledgerhq/hw-transport-node-hid").default;

var Web3 = require("web3");

var engine = new ProviderEngine();

let LedgerProvider = function(network_id, account_number, provider_url) {
  const getTransport = () => TransportU2F.create();
  const ledger = createLedgerSubprovider(getTransport, {
    networkId: network_id,
    accountsOffset: account_number
  });
  engine.addProvider(ledger);
  engine.addProvider(new FiltersSubprovider());
  engine.addProvider(new ProviderSubprovider(new Web3.providers.HttpProvider(provider_url)))
  engine.start();
  return engine;

};

let TrezorProvider = function(path, provider_url) {

  engine.addProvider(new TrezorSubprovider(path));
  engine.addProvider(new FiltersSubprovider());
  engine.addProvider(new Web3Subprovider(new Web3.providers.HttpProvider(provider_url)));
  engine.start();
  return engine;

};

let WalletProvider = function(wallet, password, provider_url, address_index) {

  if (address_index == null) {
    address_index = 0;
  }

  this.wallet = Wallet.fromV3(wallet, password, true);
  address = "0x" + this.wallet.getAddress().toString("hex");

  engine = new ProviderEngine();
  engine.addProvider(new WalletSubprovider(this.wallet, {}));
  engine.addProvider(new FiltersSubprovider());
  engine.addProvider(new Web3Subprovider(new Web3.providers.HttpProvider(provider_url)));
  return engine.start(); // Required by the provider engine.
};

let MnemonicProvider = function(mnemonic, provider_url, address_index=0, num_addresses=1) {
  mnemonic = mnemonic;
  hdwallet = hdkey.fromMasterSeed(bip39.mnemonicToSeed(mnemonic));
  wallet_hdpath = "m/44'/60'/0'/0/";
  wallets = {};
  addresses = [];

  for (let i = address_index; i < address_index + num_addresses; i++){
    var wallet = this.hdwallet.derivePath(this.wallet_hdpath + i).getWallet();
    var addr = '0x' + wallet.getAddress().toString('hex');
    addresses.push(addr);
    wallets[addr] = wallet;
  }

  const tmp_accounts = this.addresses;
  const tmp_wallets = this.wallets;

  engine = new ProviderEngine();
  engine.addProvider(new HookedSubprovider({
    getAccounts: function(cb) { cb(null, tmp_accounts) },
    getPrivateKey: function(address, cb) {
      if (!tmp_wallets[address]) { return cb('Account not found'); }
      else { cb(null, tmp_wallets[address].getPrivateKey().toString('hex')); }
    },
    signTransaction: function(txParams, cb) {
      let pkey;
      if (tmp_wallets[txParams.from]) { pkey = tmp_wallets[txParams.from].getPrivateKey(); }
      else { cb('Account not found'); }
      var tx = new Transaction(txParams);
      tx.sign(pkey);
      var rawTx = '0x' + tx.serialize().toString('hex');
      cb(null, rawTx);
    },
    signPersonalMessage(message, cb) {
      const dataIfExists = message.data;
      if (!dataIfExists) {
        cb('No data to sign');
      }
      if (!tmp_wallets[message.from]) {
        cb('Account not found');
      }
      let pkey = tmp_wallets[message.from].getPrivateKey();
      var dataBuff = ethUtil.toBuffer(dataIfExists);
      var msgHashBuff = ethUtil.hashPersonalMessage(dataBuff);
      var sig = ethUtil.ecsign(msgHashBuff, pkey);
      var rpcSig = ethUtil.toRpcSig(sig.v, sig.r, sig.s);
      cb(null, rpcSig);
    }
  }));
  engine.addProvider(new FiltersSubprovider());
  engine.addProvider(new Web3Subprovider(new Web3.providers.HttpProvider(provider_url)));
  return engine.start(); // Required by the provider engine.
};

let PrivateKeyProvider = function (privateKeys, providerUrl) {

  this.wallets = {};
  this.addresses = [];

  // from https://github.com/trufflesuite/truffle-hdwallet-provider/pull/25/commits
  for (let key of privateKeys) {
    var wallet = Wallet.fromPrivateKey(new Buffer(key, "hex"));
    var addr = '0x' + wallet.getAddress().toString('hex');
    this.addresses.push(addr);
    this.wallets[addr] = wallet;
  }

  const tmpAccounts = this.addresses;
  const tmpWallets = this.wallets;

  this.engine = new ProviderEngine()

  // from https://github.com/trufflesuite/truffle-hdwallet-provider/pull/66
  this.engine.addProvider(new NonceSubProvider())
  this.engine.addProvider(
    new HookedSubprovider({
      getAccounts: function (cb) {
        cb(null, tmpAccounts)
      },
      getPrivateKey: function (address, cb) {
        if (!tmpWallets[address]) {
          return cb('Account not found')
        } else {
          cb(null, tmpWallets[address].getPrivateKey().toString('hex'))
        }
      },
      signTransaction: function (txParams, cb) {
        let pkey
        if (tmpWallets[txParams.from]) {
          pkey = tmpWallets[txParams.from].getPrivateKey()
        } else {
          cb('Account not found')
        }
        var tx = new Transaction(txParams)
        tx.sign(pkey)
        var rawTx = '0x' + tx.serialize().toString('hex')
        cb(null, rawTx)
      }
    })
  )
  this.engine.addProvider(new FiltersSubprovider());
  this.engine.addProvider(new ProviderSubprovider(new Web3.providers.HttpProvider(providerUrl)));
  this.engine.start(); // Required by the provider engine.
}

WalletProvider.prototype.sendAsync = function() {
  this.engine.sendAsync.apply(this.engine, arguments);
};

WalletProvider.prototype.send = function() {
  return this.engine.send.apply(this.engine, arguments);
};

WalletProvider.prototype.getAddress = function() {
  return this.address;
};

MnemonicProvider.prototype.sendAsync = function() {
  this.engine.sendAsync.apply(this.engine, arguments);
};

MnemonicProvider.prototype.send = function() {
  return this.engine.send.apply(this.engine, arguments);
};

MnemonicProvider.prototype.getAddress = function() {
  return this.address;
};

TrezorProvider.prototype.sendAsync = function() {
  this.engine.sendAsync.apply(this.engine, arguments);
};

TrezorProvider.prototype.send = function() {
  return this.engine.send.apply(this.engine, arguments);
};

TrezorProvider.prototype.getAddress = function() {
  return this.address;
};

LedgerProvider.prototype.sendAsync = function() {
  this.engine.sendAsync.apply(this.engine, arguments);
};

LedgerProvider.prototype.send = function() {
  return this.engine.send.apply(this.engine, arguments);
};

LedgerProvider.prototype.getAddress = function() {
  return this.address;
};

PrivateKeyProvider.prototype.sendAsync = function () {
  this.engine.sendAsync.apply(this.engine, arguments)
}

PrivateKeyProvider.prototype.send = function () {
  return this.engine.send.apply(this.engine, arguments)
}

PrivateKeyProvider.prototype.getAddress = function (idx) {
  console.log('getting addresses', this.addresses[0], idx)
  if (!idx) {
    return this.addresses[0]
  } else {
    return this.addresses[idx]
  }
}

PrivateKeyProvider.prototype.getAddresses = function () {
  return this.addresses
}

module.exports.TrezorProvider = TrezorProvider;
module.exports.WalletProvider = WalletProvider;
module.exports.TrezorProvider = TrezorProvider;
module.exports.LedgerProvider = LedgerProvider;
module.exports.PrivateKeyProvider = PrivateKeyProvider;
