"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the 
 * password safe application.  The other file, client.js, must not be
 * modified.  That file handles page navigation, event handler binding, token 
 * setting/retrieving, preflighting, and provides some utility functions that 
 * this file should use for encoding/decoding strings and making server 
 * requests.
 *
 * Do not use any method other than serverRequest to make requests to the 
 * server!  It handles a few things including tokens that you must not
 * reimplement.
 *
 * Some of the functions in this file handle a form submission.  These 
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element 
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output 
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.  It should populate the password form
 *                 element with the decrypted password.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client 
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be 
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - randomBytes -- Takes a number of bytes as an argument and returns
 *                    that number of bytes of crypto-safe random data
 *                    as a hexidecimal-encoded string.
 *   - hash -- Takes a string as input and hashes it using SHA-256.
 *             Returns a promise for the hashed value.
 *   - encrypt -- Takes a plaintext string, a key and an IV and encrypts
 *                the plaintext using AES-CBC with the key and IV.  The
 *                key must be a 32 byte hex-encoded string and the IV must
 *                be a 16 byte hex-encoded string.
 *                Returns a promise for the encrypted value, which is a 
 *                hex-encoded string.
 *   - decrypt -- Takes a ciphertext hex-encoded string, a key and an IV and
 *                decrypts the ciphertext using AES-CBC with the key and IV.
 *                The key must be a 32 byte hex-encoded string and the IV
 *                must be a 16 byte hex-encoded string.
 *                Returns a promise for the decrypted value, which is a 
 *                plaintext string.
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is 
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for promises!
 *      https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
 *
 * There are lots of resources online for how to use promises, so go learn
 * about them before starting on the project. It is crucial that students 
 * understand how promises work, since they are used throughout the boilerplate.
 *
 *****************************************************************************/


/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */ 
async function credentials(username, password) {
  var idResult;
  
  // get any information needed to log in
  idResult = await serverRequest("identify", {"username":username});
  // bail if something went wrong
  if (!idResult.response.ok) {
    serverStatus(idResult);
    return 0;
  }

  return idResult.json;
}

/**
 * Called when the user submits the log-in form.
 */
function login(userInput, passInput) {
  // get the form fields
  var username = userInput.value,
      password = passInput.value;
      
  credentials(username, password).then(function(idJson) {
    // do any needed work with the credentials

    if (idJson) {
      // hash password with salt and use to encrypt challenge
      var salt = idJson.salt;
      var challenge = idJson.challenge;
      var initializationVector = randomBytes(16);

      hash(password + salt).then(function (key) {
        return encrypt(challenge, key, initializationVector);
      })
      .then(function(ciphertext) {
        return serverRequest("login", {"username": username, "ciphertext": ciphertext, "initializationVector": initializationVector});
      })
      .then(function(result) {
        // If the login was successful, show the dashboard.
        if (result.response.ok) {
          // do any other work needed after successful login here

          // set master password for client to send to server for encrypting 
          sessionStorage.setItem("masterKey", password);
          
          // display the user's full name in the userdisplay field
          document.getElementById("userdisplay").innerHTML = result.json.fullname;
          // userdisplay refers to the DOM element that students will need to
          // update to show the data returned by the server.
        
          showContent("dashboard");

        } else {
          // If the login failed, show the login page with an error message.
          serverStatus(result);
        }
      });
    } else {
      status('The entered username or password is incorrect.');
    }
  });
}

/**
 * Called when the user submits the signup form.
 */
function signup(userInput, passInput, passInput2, emailInput, fullNameInput) {
  // get the form fields
  var username  = userInput.value,
      password  = passInput.value,
      password2 = passInput2.value,
      email     = emailInput.value,
      fullname  = fullNameInput.value;

  // do any preprocessing on the user input here before sending to the server
  if (password !== password2) {
    status('Password fields do not match!')
  } else {
    // send the signup form to the server
    serverRequest("signup",  // resource to call
                  {"username":username, "password":password, "email":email, "fullname":fullname} // this should be populated with needed parameters
    ).then(function(result) {
      // if everything was good
      if (result.response.ok) {
        // do any work needed if the signup request succeeded

        // go to the login page
        showContent("login");
      }
      // show the status message from the server
      serverStatus(result);
    });
  }
}


/**
 * Called when the add password form is submitted.
 */
function save(siteIdInput, siteInput, userInput, passInput) {
  // has to be implemented this way because we can't edit the client code
  // if site credentials are retrieved on load page, the site id is saved in the hidden input field
  // this input field value is not reset if you navigate away from the load page
  // the siteIdInput element stores the value from the load page and even if an existing site is not selected
  // on the save page, the site id is still populated and therefore the site id is sent to the server
  // making the server believe that an update is being performed instead of an insertion
  var siteid = document.querySelector("select[name=sitelist]").selectedIndex == 0 ? "" : siteIdInput.value

  var site     = siteInput.value,
    siteuser   = userInput.value,
    sitepasswd = passInput.value;

  var masterKey = sessionStorage.getItem("masterKey");
  var siteiv = randomBytes(16);

  hash(masterKey).then(function (hexMasterKey) {
    return encrypt(sitepasswd, hexMasterKey, siteiv);
  })
  .then(function(encryptedPassword) {
    return serverRequest("save", {"siteid": siteid, "site": site, "siteuser": siteuser, "sitepasswd": encryptedPassword, "siteiv": siteiv}); // this should be populated with any parameters the server needs
  }).then(function(result) {
    if (result.response.ok) {
      // update the sites list
      sites("save");
    }
    // show any server status messages
    serverStatus(result);
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteid is a string (the site to load) and not
 * a form element.
 */
function loadSite(siteid, siteIdElement, siteElement, userElement, passElement) {
  serverRequest("load", // the resource to call
                {"siteid":siteid} // populate with any parameters the server needs
  ).then(function(result) {
    if (result.response.ok) {
      var site = result.json.site;
      var siteuser = result.json.siteuser;
      var sitepasswd = result.json.sitepasswd;
      var siteiv = result.json.siteiv;
      
      // decrypt sitepasswd

      hash(sessionStorage.getItem("masterKey")).then(function (hexMasterKey) {
        return decrypt(sitepasswd, hexMasterKey, siteiv);
      }).then(function (decryptedPassword) {
        if (siteIdElement)
          siteIdElement.value = siteid;

        siteElement.value = site;
        userElement.value = siteuser;
        passElement.value = decryptedPassword;
        // sessionStorage.setItem("siteid", siteid);
      });

    } else {
      // on failure, show the login page and display any server status
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // do any preprocessing needed
  // tell the server to log out
  serverRequest("logout", {}).then(function(result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}