if (global === undefined) {
  var global = window;
}

function isEncryptedData(value){
  return value.startsWith('##') && value.indexOf('%') == 16;
}

function processError(callback, error){
  if(typeof callback == 'function'){ callback(error, undefined); return; }else throw error;
}

global.sendMail = function({
  /* message content */ from, to, /* either recommended */ text, html,  /* optional */ cc, bcc, subject, //attachments = [], // attachments not supported yet
  onebyone = false,
  transport, // don't use ,;:\@ in the password, it makes troubles in urls
  // falls back to js promise if no callback.
  /* Action after sending */ callback,
  endpoint='https://smtpwebrelay.mayetsoft.fr/send',
  consoleLog = false,
}){

  if(!callback){
    return new Promise((resolve, reject) => {
      global.sendMail({from, to, text, html, cc, bcc, subject, /*attachments,*/ transport,
        callback: (err, data) => err ? reject(err) : resolve(data), promise: false, consoleLog, endpoint});
    });
  }

  var emailValidate = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;  // from https://emailregex.com/
  if(!from || (!isEncryptedData(from) && !emailValidate.test(from))) // if is not encrypted and not a valid email address, error (encrypted data are checked on server)
    return processError(new Error('The address in the field "from" is missing or is not a valid email address.'));
  if(!to || (!isEncryptedData(to) && !emailValidate.test(to)))  // if is not encrypted and not a valid email address, error (encrypted data are checked on server)
    return processError(new Error('The address in the field "to" is missing or is not a valid email address.'));

  var params = 'from=' + encodeURIComponent(from) + '&to=' + encodeURIComponent(to)

  if(subject) params += '&subject=' + encodeURIComponent(subject);
  if(text) params += '&text=' + encodeURIComponent(text);
  if(html) params += '&html=' + encodeURIComponent(html);

  // // group attachment in case somebody decided to add both attachment and attachments
  // if(attachments && !Array.isArray(attachments)) attachments = [attachments];
  // // process and add attachments
  // if(Array.isArray(attachments) && attachments.length > 0){
  //   for (var i = 0; i < attachments.length; i++) {
  //     params += ((i==0)?'&attachment=' :',') + encodeURIComponent(attachments[i])
  //   }
  // }
  // // TODO check sizes
  // // TODO throw error if issue on attachments
  // attachments: [
  //   { // Use a URL as an attachment
  //     filename: 'your-testla.png',
  //     path: 'https://media.gettyimages.com/photos/view-of-tesla-model-s-in-barcelona-spain-on-september-10-2018-picture-id1032050330?s=2048x2048'
  // }

  if(transport){
    if(typeof transport === 'object'){
      params += '&transport=' + encodeURIComponent(JSON.stringify(transport));
    }else if(typeof transport === 'string' && transport[0] == '#' && transport[0] == '#'){
      params += '&transport=' + encodeURIComponent(transport);
    }else{
      var error = new Error('No identification provided, you must provide an SMTP string, encrypted or not.')
      if(typeof callback == 'function'){ callback(error, undefined); return; }else throw error;
    }
  }else{
    var error = new Error('No transport provided, you must provide a SMTP server connection, encrypted or not.')
    if(typeof callback == 'function'){ callback(error, undefined); return; }else throw error;
  }

  var method = 'POST';

  // create CORS setRequestHeader
  var request = new XMLHttpRequest();
  if('withCredentials' in request){
    request.open(method, endpoint);
  }else{
    if('undefined' != typeof XDomainRequest){ // for IE 8-10
      request = new XDomainRequest();
      request.open(method, endpoint);
    }else{
      var error = new Error('Cannot send AJAX request, browser does not seem to support "XMLHttpRequest" or "XDomainRequest"');
      if(typeof callback == 'function'){ callback(error, undefined); return; }else throw error;
    }
  }

  // send AJAX reqest
  request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  request.onreadystatechange = function() { //Appelle une fonction au changement d'état.
    if (this.readyState === XMLHttpRequest.DONE && this.status === 200) {
      if(consoleLog) {console.log('Email sent to ' + to)}
      if(callback) callback(undefined, request.responseText);
    }
  }
  // request.onload = function() { //for GET
  //   if(consoleLog) {console.log('Email sent to ' + to)}
  //   if(callback) callback(undefined, request.responseText);
  // };
  console.log("request params", params);
  request.send(params);
    //{ from, to, subject, text, host, username, password }
};
