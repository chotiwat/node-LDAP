var assert = require('assert');
var util = require('util');
var LDAP = require('../LDAP');

var ldapConfig = {
  server: 'localhost:1234',
  base: 'dc=sample,dc=com',
  attr: 'cn',
  binddn: 'cn=manager,dc=sample,dc=com',
  password: 'secret',
  maxConnectRetries: 3,
  retryWait: 100
};

function deepInspect(obj, level) {
  return util.inspect(obj, false, level || 10);
}

function printOK(testName) {
  console.warn(testName + ' [OK]');
}

function ldapInit(/* [bindOption], callback */) {
  var callback = arguments[arguments.length - 1];
  var binddn = ldapConfig.binddn;
  var password = ldapConfig.password;
  var querytimeout = null;
  if(arguments.length === 2) {
    var bindOption = arguments[0];
    binddn = bindOption.dn || binddn;
    password = bindOption.password || password;
    querytimeout = bindOption.querytimeout;
  }
  
  var ldap = new LDAP.Connection();
  ldap.maxconnectretries = 3;
  ldap.retrywait = 100;
  ldap.querytimeout = querytimeout;
  
  if(ldap.open('ldap://' + ldapConfig.server) < 0) {
    throw new Error('Cannot open LDAP connection to ' + server);
  }
  
  ldap.simpleBind(binddn, password, function(msgId, err) {
    if(err) {
      callback(err, null);
    } else {
      callback(null, ldap);
    }
  });
}


var disconnected = false;
var ldap = null;
// begin test
test1();

// test connect
function test1() {
  var cnx = new LDAP.Connection();
  cnx.maxconnectretries = 3;
  cnx.retrywait = 100;
  
  var resultSuccess = cnx.open('ldap://' + ldapConfig.server);
  assert.ok(resultSuccess >= 0, 'connect to ldap server failed result = ' + resultSuccess);
  cnx.close();
  
  printOK('test1');
  
  test2();
}

// test simplebind
function test2() {
  var cnx = new LDAP.Connection();
  cnx.maxconnectretries = 3;
  cnx.retrywait = 100;
  
  cnx.open('ldap://' + ldapConfig.server);
  cnx.simpleBind(ldapConfig.binddn, ldapConfig.password, bound);
  
  function bound(msgId, err) {
    assert.ok(!err, err);
    
    cnx.simpleBind(ldapConfig.binddn, 'wrongpassword', boundFail);
  }
  
  function boundFail(msgId, err) {
    assert.ok(err);
    
    cnx.simpleBind('cn=nobody,dc=nowhere,dc=no', ldapConfig.password, boundNonUser);
  }
  
  function boundNonUser(msgId, err) {
    assert.ok(err);
    cnx.close();
    
    cnx.open('ldap://no.lookup:90909');
    cnx.simpleBind(ldapConfig.binddn, ldapConfig.password, boundNonServer);
  }
  
  function boundNonServer(msgId, err) {
    assert.ok(err);
    cnx.close();
    printOK('test2');
    test3();
  }
}

// test search
function test3() {
  ldapInit(bound);
  
  function bound(err, cnx) {
    assert.ok(!err);
    
    ldap = cnx;
    ldap.addListener('disconnected', function() {
      disconnected = true;
    });
    ldap.search('dc=sample,dc=com', ldap.SUBTREE, '(cn=Manager)', '*', function(msgId, err, res) {
      assert.ok(!err);
      assert.equal(res.length, 1);
      assert.equal(res[0].cn[0], 'Manager');
      printOK('test3');
      test4();
    });
  }
}

// test search fail
function test4() {
  ldap.search('dc=sample,dc=com', ldap.SUBTREE, '(cn=xManager)', '*', function(msgId, err, res) {
    assert.ok(!err);
    assert.equal(res.length, 0);
    printOK('test4');
    test5();
  });
}

// test add
function test5() {
  ldap.add('cn=Barbara Jensen,dc=sample,dc=com', [
    { type: 'objectClass',
      vals: ['person']},
    { type: 'cn',
      vals: ['Barbara Jensen', 'Babs Jensen'] },
    { type: 'sn',
      vals: ['Jensen']}
  ],
  function(msgId, err) {
    assert.ok(!err, deepInspect(err));
    printOK('test5');
    test6();
  });
}

function test6() {
    ldap.search('dc=sample,dc=com', ldap.SUBTREE, 'cn=Babs Jensen', '*', function(msgId, err, res) {
      assert.ok(!err);
      assert.equal(res.length, 1, 'No results from search where results expected');
      printOK('test6');
      test7();
    });
}

// function search_after_disconnect() {
function test7() {
  setTimeout(function() {
    assert.ok(disconnected);
    ldap.search('dc=sample,dc=com', ldap.SUBTREE, 'cn=Babs Jensen', '*', function(msgId, err, res) {
      assert.ok(!err, deepInspect(arguments));
      printOK('test7');
      test8();
    });
  }, 5000);
}

// test ldap modify
function test8() {
  var barbara = 'cn=Barbara Jensen,dc=sample,dc=com';
  ldap.modify(barbara, [
    {
      type: 'sn',
      vals: ['x1', 'x5', 'x6']
    },
    {
      op: 'add',
      type: 'description',
      vals: ['test']
    },
    {
      op: 'add',
      type: 'sn',
      vals: ['x2', 'x3', 'x4']
    },
    {
      op: 'delete',
      type: 'cn',
      vals: ['Babs Jensen']
    }
  ], modified);
  
  function modified(msgId, err) {
    assert.ok(!err, deepInspect(err));
    ldap.search(barbara, ldap.BASE, 'cn=*', '*', searched);
    
  }
  
  function searched(msgId, err, res) {
    assert.ok(!err, deepInspect(arguments));
    assert.ok(res);
    assert.equal(res.length, 1);
    
    var entry = res[0];
    assert.deepEqual(entry.cn, ['Barbara Jensen']);
    assert.deepEqual(entry.sn.sort(), ['x1', 'x5', 'x6', 'x2', 'x3', 'x4'].sort());
    assert.deepEqual(entry.description, ['test']);
    
    ldap.modify(barbara, [
      {
        op: 'delete',
        type: 'description',
        vals: []
      }
    ], modifiedAgain);
  }
  
  function modifiedAgain(msgId, err) {
    assert.ok(!err);
    ldap.search(barbara, ldap.BASE, 'cn=*', '*', searchedAgain);
  }
  
  function searchedAgain(msgId, err, res) {
    assert.ok(!err);
    assert.ok(res.length, 0);
    assert.ok(!('description' in res[0]), deepInspect(arguments));
    printOK('test8');
    test9();
  }
}

// test delete entry
function test9() {
  var dn = 'cn=To be deleted,dc=sample,dc=com';
  ldap.add(dn, [
    { type: 'objectClass',
      vals: ['person']},
    { type: 'cn',
      vals: ['To be deleted', '2bdeleted'] },
    { type: 'sn',
      vals: ['Temp']}
  ], function added(msgId, err) {
    assert.ok(!err);
    ldap.remove(dn, removed);
  });
  
  var count = 0;
  
  function removed(msgId, err) {
    assert.ok(!err);
    ldap.search(dn, ldap.BASE, 'cn=*', '*', searched);
    ldap.search(ldapConfig.base, ldap.SUBTREE, 'cn=To be deleted', '*', subtreeSearched)
  }
  
  function subtreeSearched(msgId, err, res) {
    assert.ok(!err);
    assert.ok(res);
    assert.equal(res.length, 0);
    if(++count === 2) {
      printOK('test9');
      test10();
    }
  }
  
  function searched(msgId, err, res) {
    assert.ok(err)
    assert.equal(err.message, '32');
    if(++count === 2) {
      printOK('test9');
      test10();
    }
  }
}

// test dereferencing search
function test10() {
  var simpleRes = null;
  ldap.add('cn=Alias,dc=sample,dc=com', [
    {
      type: 'objectClass',
      vals: ['alias', 'extensibleObject']
    },
    {
      type: 'cn',
      vals: ['Alias']
    },
    {
      type: 'aliasedObjectName',
      vals: ['cn=Barbara Jensen,dc=sample,dc=com']
    }
  ], aliasAdded);
  
  
  
  function aliasAdded(msgId, err) {
    assert.ok(!err);
    ldap.searchDeref(ldapConfig.base, ldap.SUBTREE, 'cn=*', '*', ldap.DEREF_NEVER, simpleSearched);
    ldap.search(ldapConfig.base, ldap.SUBTREE, 'cn=*', '*', simpleSearched);
  }
  
  function simpleSearched(msgId, err, res) {
    assert.ok(!err, deepInspect(err));
    assert.ok(res);
    assert.equal(res.length, 3);
    if(simpleRes) {
      assert.deepEqual(simpleRes, res);
      ldap.searchDeref(ldapConfig.base, ldap.SUBTREE, 'cn=*', '*', ldap.DEREF_ALWAYS, derefSearched);
    } else {
      simpleRes = res;
    }
  }
  
  function derefSearched(msgId, err, res) {
    assert.ok(res, deepInspect(res));
    assert.equal(res.length, 2);
    ldap.searchDeref('cn=Alias,dc=sample,dc=com', ldap.BASE, 'cn=*', '*', ldap.DEREF_ALWAYS, derefBaseSearched);
  }
  
  function derefBaseSearched(msgId, err, res) {
    assert.ok(res, deepInspect(res));
    assert.equal(res.length, 1);
    assert.equal(res[0].cn[0], 'Barbara Jensen');
    printOK('test10');
    test11();
  }
  
}

// prepare entry for search test
function test11() {
  var dn = 'ou=tests,dc=sample,dc=com';
  var aliasdn= 'ou=alias,dc=sample,dc=com';
  var count = 0;
  var aliasCount = 0;
  var maxConnection = 100; // maximum should not be more than 100
  var multiplier = 100;
  var max = maxConnection * multiplier;
  var start;
  var connectionList = [];
  
  var simpleSum = 0;
  var aliasSum = 0;
  
  ldap.add(dn, [
    { type: 'objectClass',
      vals: ['organizationalUnit']},
    { type: 'ou',
      vals: ['tests'] }
  ], added);
  
  function added(msgId, err) {
    assert.ok(!err);
    ldap.add(aliasdn, [
      { type: 'objectClass',
        vals: ['organizationalUnit']},
      { type: 'ou',
        vals: ['alias'] }
    ], aliasTreeAdded);
  }
  
  function aliasTreeAdded(msgId, err) {
    assert.ok(!err);
    for(var i = 0; i < maxConnection; i++) {
      ldapInit({ querytimeout: 3600000 }, function(err, ldap) {
        assert.ok(!err, JSON.stringify(err));
        connectionList.push(ldap);
        
        if(connectionList.length == maxConnection) {
          start = new Date();
          connectionList.forEach(function(ldap, i) {
            for(var j = 0; j < multiplier; j++) {
              var k = i * multiplier + j;
              var userdn;
              ldap.add(userdn = 'cn=user' + k + ',' + dn, [
                { type: 'objectClass',
                  vals: ['person']},
                { type: 'cn',
                  vals: ['user' + k] },
                { type: 'sn',
                  vals: ['test']}
              ], userAdded);
              
              ldap.add('cn=user' + k + ',' + aliasdn, [
                { type: 'objectClass',
                  vals: ['alias', 'extensibleObject']},
                { type: 'cn',
                  vals: ['user' + k] },
                { type: 'aliasedObjectName',
                  vals: [userdn]}
              ], aliasAdded);
            }
          });
        }
      });
    }
    
  }
  
  function userAdded(msgId, err) {
    console.log(count+1);
    assert.ok(!err, err);
    if(++count == max && aliasCount == max) {
      bothAdded();
    }
  }
  
  function aliasAdded(msgId, err) {
    console.log((aliasCount+1) + ' a');
    assert.ok(!err, err);
    if(++aliasCount == max && count == max) {
      bothAdded();
    }
  }
  
  function bothAdded() {
    console.error(new Date() - start);
    connectionList.forEach(function(ldap) {
      ldap.close();
    });
    
    individualTest(0);
    
    // printOK('test11');
    // done();
  }
  
  function individualTest(x) {
    if(x == max) {
      individualAliasTest(0);
      return;
    }
    
    var start1 = new Date().getTime();
    ldap.search(dn, ldap.SUBTREE, 'cn=user' + x, '*', function searched(msgId, err, res) {
      var time = new Date().getTime() - start1;
      assert.ok(!err, err);
      assert.equal(res.length, 1);
      console.log(x + ': ' + time);
      simpleSum += time;
      process.nextTick(function() {
        individualTest(x + 1);
      });
    });
  }
  
  function individualAliasTest(x) {
    if(x == max) {
      console.log('simple search: ' + simpleSum + ' (' + (simpleSum/max) + ' avg.)');
      console.log('alias search: ' + aliasSum + ' (' + (aliasSum/max) + ' avg.)');
      printOK('test11');
      done();
      return;
    }
    
    var start2 = new Date().getTime();
    ldap.searchDeref(aliasdn, ldap.SUBTREE, 'cn=user' + x, '*', ldap.DEREF_ALWAYS, function searched(msgId, err, res) {
      var time = new Date().getTime() - start2;
      assert.ok(!err, err);
      assert.equal(res.length, 1);
      console.log(x + 'a: ' + time);
      aliasSum += time;
      process.nextTick(function() {
        individualAliasTest(x + 1);
      });
    });
  }
}

function done() {
  ldap.close();
  console.log('Finish');
}
