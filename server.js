const port = process.env.PORT || 3000;
const encryptionKey = process.env.ENCRYPTION_KEY || "12345678901234567890123456789012";
const rootURL = process.env.ROOT_URL || "";

// Nodes modules, not packages
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// import packages
const express = require("express");
const bodyParser = require('body-parser');
const multer = require('multer');

const nodemailer = require('nodemailer');
const htmlToText = require('nodemailer-html-to-text').htmlToText;

const upload = multer();
const app = express();

function logRequest(req){
  console.log(
    new Date().toISOString() +
    '\t' + req.ips.concat([req.ip]).toString() +
    '\t' + req.get('Referrer'),
    '\t' + req.protocol + '://' + req.hostname + req.path +
    '\t' + req.baseUrl
  );
}

app.listen(port, () => {
 console.log("SMTP web relay Server running on port "+ port);
});

////////////////////////////////////// input parsers used in /crypt and /send ///////////////////////////////////////

const jsonParser = bodyParser.json(); // for parsing application/json  -- {limit: '1mb'}
const urlEncodedParser = bodyParser.urlencoded({ extended: true }); // for parsing application/xwww-form-urlencoded -- limit: '1mb'
// app.use(bodyParser.raw({limit: '1mb'})); // Maybe more limits to apply later
// app.use(bodyParser.text({limit: '1mb'}));
const uploaderAarray = upload.array(); // for parsing multipart/form-data


///////////////////////////////////////////// encryption features //////////////////////////////////////////////////
function getDecryptedValue(value, referrer){
  if(value && isEncryptedData(value)) return decryptData(value, referrer);
  else return value;
}

function isEncryptedData(value){
  return value.startsWith('##') && value.indexOf('%') == 34;
}


const referrerSplitMarker = ' ||##|| ';
function encryptData(value, referrer){
  const data = JSON.stringify(value)+referrerSplitMarker+referrer;
  const iv = crypto.randomBytes(16); // random initialization vector for additional security (has to be unique).

  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  return '##'+iv.toString('hex')+'%'+Buffer.concat([cipher.update(data), cipher.final()]).toString('hex'); // concat iv so that the client can give it back for decription. It does not have to be secret but has to be unique.
};

function decryptData(value, referrer){
  const [ivHex, encryptedData] = value.substring(2).split('%'); // get iv and encrypted data based on the concat scheme we have on the encrypt() function
  if(ivHex && encryptedData){
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const [data, decryptReferrer] = decrypted.toString().split(referrerSplitMarker);
    if(decryptReferrer != referrer){
        throw new ReferrerError('Origin of call is different to encrypted data allowed referrer. ['+decryptReferrer+' / '+referrer+']');
    }
    return JSON.parse(data);
  }
};

const emailValidate = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;  // from https://emailregex.com/
function isValidEmail(email){
  return emailValidate.test(email);
}

function ReferrerError(message){
    this.message = message;
}
ReferrerError.prototype = new Error();

app.post("/crypt", [jsonParser, urlEncodedParser, uploaderAarray], (req, res, next) => {
  logRequest(req);
  if(!req.body.hasOwnProperty('value')){
    res.json({error: "Value is missing, nothing to encrypt."});
  }else if(!req.body.hasOwnProperty('referrer')){
    res.json({error: "Referrer is missing, the value wouldn't be usable by the server."});
  }else{
    res.json(encryptData(req.body.value, req.body.referrer));
  }
});

///////////////////////////////////////// serve the library //////////////////////////////////////////////
// serve the library file (cdn-style)
app.get("/lib", (req, res, next) => {
  logRequest(req);
  res.sendFile(path.join(__dirname + '/client/smtpwebrelay.js'));
});

// serve library file to be downloaded
app.get('/smtpwebrelay.js', function(req, res){
  logRequest(req);
  const file = fs.readFileSync(__dirname + '/client/smtpwebrelay.min.js', 'binary'); // serve minified anyway. Full version is for development and available on the repository
  res.setHeader('Content-Length', file.length);
  res.write(file, 'binary');
  res.end();
});

app.get('/smtpwebrelay.min.js', function(req, res){
  logRequest(req);
  const file = fs.readFileSync(__dirname + '/client/smtpwebrelay.min.js', 'binary');
  res.setHeader('Content-Length', file.length);
  res.write(file, 'binary');
  res.end();
});


///////////////////////////////////////////   process email sending /////////////////////////////////////////////

const messageFields = ["to","cc","bcc","subject","text","html","sender","replyTo","inReplyTo","references","attachDataUrls","watchHtml","amp","encoding","raw","textEncoding","priority","headers","messageId","date","list"];
// from, redirect, onebyone, transport -> processed indepentently // TODO add attachments processing
const recipientsFields = ["to", "cc", "bcc"];
const transportFields = ["port", "host", "authMethod", "secure", "connectionTimeout", "greetingTimeout", "socketTimeout", "pool", "maxConnections", "maxMessages", "rateDelta", "rateLimit", "proxy"];
const authFields = ["type","user","pass", "type", "clientId", "clientSecret", "refreshToken", "accessToken", "expires", "accessUrl", "serviceClient", "privateKey"]; // auth

app.post("/send", [jsonParser, urlEncodedParser, uploaderAarray], async (req, res, next) => {
  logRequest(req);

  try{
    const referrer = req.get('Referrer');

    const transportUserSettings = JSON.parse(getDecryptedValue(req.body.transport, referrer));
    if(!transportUserSettings){
      const errMessage = "Invalid SMTP details in transport object";
      if(req.body.redirect){
        res.send("Error sending email: " + errMessage);
      }else{
        // res.status(435);
        res.json({ error: errMessage });
      }
    }else{ // valid transportUserSettings

      const message = {};
      for (let i = 0; i < messageFields.length; i++) {
        if(req.body.hasOwnProperty(messageFields[i])){
          message[messageFields[i]] = getDecryptedValue(req.body[messageFields[i]], referrer); // every field but attachments can be encrypted, more flexible
        }
      }

      const from = getDecryptedValue(req.body.from, referrer);
      if(!from || !isValidEmail(from))
        throw new Error('The address in the field "from" is missing or is not a valid email address. ('+ from +")");

      let recipientCount = 0;
      for (let i = 0; i < recipientsFields.length; i++) {
        if(message.hasOwnProperty(recipientsFields[i])){
          message[recipientsFields[i]] = message[recipientsFields[i]].split(/[:;,\s]/);
          if(!message[recipientsFields[i]]){
            if(recipientsFields[i] == 'to') throw new Error('The address in the field "'+recipientsFields[i]+'" is missing.');
          }else{
            for(let j = 0; j < message[recipientsFields[i]].length; j++){
              recipientCount++;
              if(!emailValidate.test(message[recipientsFields[i]][j])){
                throw new Error('One of the address in the field "'+recipientsFields[i]+'" is not a valid email address. ('+message[recipientsFields[i]][j]+')');
              }
            }
          }
        }
      }

      // attachments not supported yet
      //message.attachments = req.body.attachments; // attachments cannot be encrypted by the current server

      const transport = {
        pool: !!(recipientCount > 1  && req.body.onebyone), // true if more than one target and set to send individual emails
        disableFileAccess: true,
      };
      for (let i = 0; i < transportFields.length; i++) {
        if(transportUserSettings.hasOwnProperty(transportFields[i]))
          transport[transportFields[i]] = transportUserSettings[transportFields[i]];

      }

      if(transportUserSettings.auth){
        transport.auth = {};
        for (let i = 0; i < authFields.length; i++) {
          if(transportUserSettings.auth.hasOwnProperty(authFields[i]))
          transport.auth[authFields[i]] = transportUserSettings.auth[authFields[i]];
        }
      }
      // if(!transport.connectionTimeout) transport.connectionTimeout = 60000; //1 min // nodemailer default is 2 min, review if it's ok for this server later

      // create transporter
      console.log("Created transporter", transport.host);
      const transporter = nodemailer.createTransport(transport, { from });

      // if there is no text information but html is provided, use the nodemailer plugin to generate a plain text version
      transporter.use('compile', htmlToText()); // options

      // verify transport configuration
      try{
        await transporter.verify();
      }catch(error){
        const errMessage = "SMTP details could not be validated";
        console.log(errMessage, transport);
        if(req.body.redirect){
          res.send("Error sending email: " + errMessage+ "."+JSON.Stringify(error));
        }else{
          res.json({ message: errMessage, error });
        }
        return;
      }

      // ready to process sending
      try{

        // onebyone email sending by merging to, cc, bcc and making one email per recipient
        if(req.body.onebyone && recipientCount > 1){
          // gather all recipients
          const recipients = [];
          for (let i = 0; i < recipientsFields.length; i++) {
            for (let j = 0; j < message[recipientsFields[i]].length; j++) {
              recipients.push(message[recipientsFields[i]][j]);
            }
            delete message[recipientsFields[i]];
          }
          // send all individual emails
          for (let k = 0; k < recipients.length; k++) {
            const oneMessage = { to: recipients[k] };
            for (var l = 0; l < messageFields.length; l++) {
              if(recipientsFields.indexOf(messageFields[l]) == -1){ // ignore to, cc & bcc as they have been folded in recipients
                if(message.hasOwnProperty(messageFields[i])){
                  oneMessage[messageFields[l]] = message[messageFields[l]]; // add all the other fields
                }
              }
            }
            await transporter.sendMail(oneMessage);
            console.log("Sent email", transporter.host, oneMessage.from, oneMessage.to);
          }
        }else{
          // send one email
          await transporter.sendMail(message);
          console.log("Sent email", transporter.host, message.from, message.to);
        }
        if(req.body.redirect){
          res.redirect(req.body.redirect);
        }else{
          res.json({success: true});
        }
      }catch(exception){
        console.log("Error: "+ exception.message, exception);
        if(req.body.redirect){
          res.send("Error sending email: " + exception.message);
        }else{
          res.json({error: exception.message});
        }
        return;
      }
    }
  }catch(exception){
    // if(exception instanceof ReferrerError){
      console.log("Error: "+ exception.message, exception);
      if(req.body.redirect){
        res.send("Error sending email: " + exception.message);
      }else{
        // res.status(439);
        res.json({error: exception.message});
      }
    // }else{} // so far no difference of treatment between ReferrerError or all errors. Return message
  }
});


///////////////////////////////////////// serve the doc website /////////////////////////////////////////////
app.use(express.static(path.join(__dirname, 'public')));


//////////////////////////////////////// serve special pages ///////////////////////////////////////////

app.get("/privacy", (req, res, next) => {
  logRequest(req);
  res.sendFile(path.join(__dirname + '/public/privacy.html'));
});

app.get("/tandc", (req, res, next) => {
  logRequest(req);
  res.sendFile(path.join(__dirname + '/public/tanc.html'));
});
