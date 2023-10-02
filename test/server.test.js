const chai = require('chai');
const expect = chai.expect;
const supertest = require('supertest');
const app = require('../server'); // Import your Express server file (server.js)

const request = supertest(app);

describe('Express Server', () => {
  it('should start the server and return a 200 OK response for the home route', async () => {
    const response = await request.get('/');
    expect(response.status).to.equal(200);
    expect(response.text).to.include('OIDC Webapp sample Nodejs');
  });

  it('should handle 404 errors for non-existing routes', async () => {
    const response = await request.get('/non-existing-route');
    expect(response.status).to.equal(404);
  });

});
