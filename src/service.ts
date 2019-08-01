require('dotenv').config();
import * as saml from 'samlify';
import * as Hapi from '@hapi/hapi';
import * as validator from '@authenio/samlify-xsd-schema-validator';
import * as jwt from 'jsonwebtoken';
import * as uuidv4 from 'uuid/v4';

import { loadParams } from './keys';

saml.setSchemaValidator(validator);
const init = async () => {
  const keys = await loadParams(['bowtie.sp.cert', 'bowtie.gsuite.key']);

  const spManifest = keys.get('bowtie.sp.cert');
  const gusiteIdp = keys.get('bowtie.gsuite.key');
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
    host: '0.0.0.0',
    port: process.env.PORT || 8006,
  });

  server.route({
    method: 'GET',
    path: '/start',
    handler: (_request, h) => {
      const login = sp.createLoginRequest(idp);
      return h.redirect(login.context);
    },
  });

  server.route({
    method: 'GET',
    path: '/metadata',
    handler: (_request, h) => {
      return h.response(sp.getMetadata()).type('text/xml');
    },
  });

  server.route({
    method: 'POST',
    path: '/gsuite/acs',
    handler: async (request, h) => {
      try {
        const response = await sp.parseLoginResponse(idp, 'post', {
          body: request.payload,
          query: request.query,
        });

        var token = jwt.sign(
          {
            id: response.extract.nameID,
            jwtid: uuidv4(),
          },
          passoffSecret,
          { expiresIn: '60s' },
        );

        return h.redirect(
          `${process.env.FALMER_ENDPOINT}/auth/sso?token=${token}`,
        );
      } catch (e) {
        console.error(e);
      }
      return 'An error occured.';
    },
  });

  await server.start();
  console.log('Server running on %ss', server.info.uri);
};

process.on('unhandledRejection', (err) => {
  console.log(err);
  process.exit(1);
});

init();
