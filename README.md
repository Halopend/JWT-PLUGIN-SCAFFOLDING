Built using WordpressMVC
Adapted from: https://github.com/usefulteam/jwt-auth

Uses composer to manage php dependencies.

Fairly barebones, but use "JWT API Testing.paw" for testing the api

Main Considerations in project setup:
- Following an MVC pattern (Sonny's Pref)
- Extending WP_REST_Controller to implement the API (Structured approach)
- Allowing the controller to handle multiple methods of username/password being supplied (url Param, form encoded, json, etc.)

The 2 end points are:
http://localhost:10013/wp-json/jwt/v1/token
http://localhost:10013/wp-json/jwt/v1/token/validate
with params username and password for getting the token, and outh2 when attempting to validate


Uncertain about full usage desired, but assuming if it's to encrypt other rest api's on the site down the road
this can also be ported from https://github.com/usefulteam/jwt-auth

Video of it in use:
https://s.tape.sh/hwE1bXpf
