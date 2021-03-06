/**
 * Created with JetBrains WebStorm.
 * User: ganyue
 * Date: 14/11/7
 * Time: 上午11:42
 * To change this template use File | Settings | File Templates.
 */

exports.initial = initial;
var oauthserver = require('oauth2-server');
function initial(app, clusterConfig) {
    app.oauth = oauthserver({
        model: require('./model'), // See below for specification
        grants: ['password','auth_code'],
        accessTokenLifetime:1*60*1000,
        debug: true
    });
    // Handle token grant requests
    app.all('/oauth/token', app.oauth.grant());

// Show them the "do you authorise xyz app to access your content?" page
    app.get('/oauth/authorise', function (req, res, next) {
        if (!req.session || !req.session.user) {
            // If they aren't logged in, send them to your own login implementation
            return res.redirect('/oauth/login?redirect=' + req.path + '&client_id=' +
                req.query.client_id + '&redirect_uri=' + req.query.redirect_uri);
        }

        res.render('authorise', {
            client_id: req.query.client_id,
            redirect_uri: req.query.redirect_uri
        });
    });

// Handle authorise
    app.post('/oauth/authorise', function (req, res, next) {
        if (!req.session.user) {
            return res.redirect('/oauth/login?client_id=' + req.query.client_id +
                '&redirect_uri=' + req.query.redirect_uri);
        }

        next();
    }, app.oauth.authCodeGrant(function (req, next) {
        // The first param should to indicate an error
        // The second param should a bool to indicate if the user did authorise the app
        // The third param should for the user/uid (only used for passing to saveAuthCode)
        next(null, true, req.session.user.id, req.session.user);
    }));

// Show login
    app.get('/oauth/login', function (req, res, next) {
        res.render('login', {
            redirect: req.query.redirect,
            client_id: req.query.client_id,
            redirect_uri: req.query.redirect_uri
        });
    });

// Handle login
    app.post('/oauth/login', function (req, res, next) {

        // Insert your own login mechanism
        if (req.body.email == 'thom@nightworld.com') {
            res.render('login', {
                redirect: req.body.redirect,
                client_id: req.body.client_id,
                redirect_uri: req.body.redirect_uri
            });
        } else {
            req.session.user = "huangzhi";
            // Successful logins should send the user back to the /oauth/authorise
            // with the client_id and redirect_uri (you could store these in the session)
            return res.redirect((req.body.redirect || '/home') + '?client_id=' +
                req.body.client_id + '&redirect_uri=' + req.body.redirect_uri);
        }
    });


    app.use(app.oauth.errorHandler());
}