require('dotenv').config()
import * as saml from 'samlify';
import * as Hapi from '@hapi/hapi';
import * as validator from '@authenio/samlify-xsd-schema-validator';
import * as jwt from 'jsonwebtoken';
import * as uuidv4 from 'uuid/v4';
import * as https from 'https';

import { loadParams } from './keys';

const greenlock = require('greenlock-hapi').create({
    version: 'draft-11' // Let's Encrypt v2
    // You MUST change this to 'https://acme-v02.api.letsencrypt.org/directory' in production
  , server: 'https://acme-staging-v02.api.letsencrypt.org/directory'
  
  , email: 'website@sussexstudent.com'
  , agreeTos: true
  , approveDomains: [ 'sso.sussexstudent.com' ]
  
    // Join the community to get notified of important updates
    // and help make greenlock better
  , communityMember: true
  
  , configDir: require('os').homedir() + '/acme/etc',
  
    store: require('greenlock-store-fs'),
  //, debug: true
  });

const httpsServer = https.createServer(greenlock.httpsOptions).listen(443);
const acmeResponder = greenlock.middleware();

saml.setSchemaValidator(validator);
const init = async () => {
    const keys = await loadParams(['bowtie.sp.cert', 'bowtie.gsuite.key']);

    const spManifest = keys.get('bowtie.sp.cert');
    const gusiteIdp = keys.get('bowtie.gsuite.key')
    const passoffSecret = process.env.PASSOFF_SECRET;

    if (!spManifest || !gusiteIdp) {
        throw new Error('failed to get secrets');
    }

    if (!passoffSecret) {
        throw new Error('passoff secret not set!');
    }

    const sp = saml.ServiceProvider({
        metadata: spManifest.Value,
      });
    
    const idp = saml.IdentityProvider({
        metadata: gusiteIdp.Value,
      });

    const server = new Hapi.Server({
        host: 'sso.sussexstudent.com',
        listener: httpsServer,
        autoListen: false,
        tls: true        
    });

    server.route({
        method: 'GET',
        path:'/start',
        handler: (_request, h) => {
            const login = sp.createLoginRequest(idp);
            return h.redirect(login.context)
        }
    });

    server.route({
        method: 'GET',
        path:'/metadata',
        handler: (_request, h) => {
            return h.response(sp.getMetadata())
                .type('text/xml')
        }
    });

    server.route({
        method: 'GET'
      , path: '/.well-known/acme-challenge'
      , handler: function (request) {
          var req = request.raw.req;
          var res = request.raw.res;
          
          acmeResponder(req, res);
        }
      });

    server.route({
        method: 'POST',
        path:'/gsuite/acs',
        handler: async (request, h) => {
            try {
                const response = await sp.parseLoginResponse(idp, 'post', {
                body: request.payload,
                query: request.query,
            });

            var token = jwt.sign({
                id: response.extract.nameID,
                jwtid: uuidv4(),
            }, passoffSecret, { expiresIn: '60s' });
            
            return h.redirect(`${process.env.FALMER_ENDPOINT}/auth/sso?token=${token}`)
        } catch (e) {
            console.error(e);
        }
            return 'An error occured.';
        }
    })

    await server.start();
    console.log('Server running on %ss', server.info.uri);
};

process.on('unhandledRejection', (err) => {

    console.log(err);
    process.exit(1);
});

init();

var http = require('http');
var redirectHttps = require('redirect-https')();

http.createServer(greenlock.middleware(redirectHttps)).listen(80, function () {
  console.log('Listening on port 80 to handle ACME http-01 challenge and redirect to https');
});