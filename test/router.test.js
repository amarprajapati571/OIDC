const chai = require('chai');
const expect = chai.expect;
const supertest = require('supertest');
const express = require('express');
const app = express();

// Import the router module
const router = require('../routes/index'); // Replace 'your-router-module' with the actual path to your router module

app.use('/', router); // Mount the router in your Express app

const request = supertest(app);

describe('Express Router Module', () => {
  it('should render the index page with a 200 OK response', async () => {
    const response = await request.get('/');
    console.log(response)
    expect(response.status).to.equal(200);
    expect(response.text).to.include('OIDC Webapp sample Nodejs');
  });

  it('should render the profile page with authentication', async () => {
    // You may need to set up authentication or mock it for this test
    // Example: Set up a mock OIDC user for authentication

    const response = await request.get('/profile');
    expect(response.status).to.equal(200);
    expect(response.text).to.include('Profile page');
  });

  it('should require authentication for the profile route', async () => {
    const response = await request.get('/profile');
    expect(response.status).to.equal(401); // Assuming that the route requires authentication
  });

});
