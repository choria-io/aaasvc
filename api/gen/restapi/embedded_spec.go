// Code generated by go-swagger; DO NOT EDIT.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "https",
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Signing service for version 1 Choria Secure Requests",
    "title": "Choria Central Signing Service",
    "version": "1.0.0"
  },
  "basePath": "/choria/v1",
  "paths": {
    "/login": {
      "post": {
        "description": "Logs into the choria service",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "summary": "Logs into the service using auth0",
        "parameters": [
          {
            "description": "The Login request",
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/LoginRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Login response",
            "schema": {
              "$ref": "#/definitions/LoginResponse"
            }
          }
        }
      }
    },
    "/sign": {
      "post": {
        "description": "Signs a Choria request",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "summary": "Sign a message",
        "parameters": [
          {
            "description": "The Choria message to sign",
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/SignRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Signature response",
            "schema": {
              "$ref": "#/definitions/SignResponse"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "LoginRequest": {
      "type": "object",
      "properties": {
        "password": {
          "description": "The password to log in with",
          "type": "string"
        },
        "public_key": {
          "description": "A ED25519 public key in hex encoded format that will be placed in the JWT and used to verify the signature",
          "type": "string"
        },
        "signature": {
          "description": "A signature made using the ED25519 private key of the time:user:pass string",
          "type": "string"
        },
        "timestamp": {
          "description": "A string holding the numeric unix timestamp",
          "type": "string"
        },
        "username": {
          "description": "The username to log in with",
          "type": "string"
        }
      }
    },
    "LoginResponse": {
      "type": "object",
      "properties": {
        "error": {
          "description": "An error message indicating why login failed",
          "type": "string"
        },
        "token": {
          "description": "The JWT token identifying the user, obtained from /login",
          "type": "string"
        }
      }
    },
    "SignRequest": {
      "type": "object",
      "properties": {
        "request": {
          "description": "base64 encoded Choria protocol.Request message to sign",
          "type": "string",
          "format": "byte"
        },
        "signature": {
          "description": "A signature, hex encoded, made using the private key matching the public key in the token",
          "type": "string"
        },
        "token": {
          "description": "The JWT token identifying the user, obtained from /login",
          "type": "string"
        }
      }
    },
    "SignResponse": {
      "type": "object",
      "properties": {
        "error": {
          "description": "An error message indicating why signing failed",
          "type": "string"
        },
        "secure_request": {
          "description": "base64 encoded protocol.SecureRequest signed message",
          "type": "string",
          "format": "byte"
        }
      }
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "https",
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Signing service for version 1 Choria Secure Requests",
    "title": "Choria Central Signing Service",
    "version": "1.0.0"
  },
  "basePath": "/choria/v1",
  "paths": {
    "/login": {
      "post": {
        "description": "Logs into the choria service",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "summary": "Logs into the service using auth0",
        "parameters": [
          {
            "description": "The Login request",
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/LoginRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Login response",
            "schema": {
              "$ref": "#/definitions/LoginResponse"
            }
          }
        }
      }
    },
    "/sign": {
      "post": {
        "description": "Signs a Choria request",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "summary": "Sign a message",
        "parameters": [
          {
            "description": "The Choria message to sign",
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/SignRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Signature response",
            "schema": {
              "$ref": "#/definitions/SignResponse"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "LoginRequest": {
      "type": "object",
      "properties": {
        "password": {
          "description": "The password to log in with",
          "type": "string"
        },
        "public_key": {
          "description": "A ED25519 public key in hex encoded format that will be placed in the JWT and used to verify the signature",
          "type": "string"
        },
        "signature": {
          "description": "A signature made using the ED25519 private key of the time:user:pass string",
          "type": "string"
        },
        "timestamp": {
          "description": "A string holding the numeric unix timestamp",
          "type": "string"
        },
        "username": {
          "description": "The username to log in with",
          "type": "string"
        }
      }
    },
    "LoginResponse": {
      "type": "object",
      "properties": {
        "error": {
          "description": "An error message indicating why login failed",
          "type": "string"
        },
        "token": {
          "description": "The JWT token identifying the user, obtained from /login",
          "type": "string"
        }
      }
    },
    "SignRequest": {
      "type": "object",
      "properties": {
        "request": {
          "description": "base64 encoded Choria protocol.Request message to sign",
          "type": "string",
          "format": "byte"
        },
        "signature": {
          "description": "A signature, hex encoded, made using the private key matching the public key in the token",
          "type": "string"
        },
        "token": {
          "description": "The JWT token identifying the user, obtained from /login",
          "type": "string"
        }
      }
    },
    "SignResponse": {
      "type": "object",
      "properties": {
        "error": {
          "description": "An error message indicating why signing failed",
          "type": "string"
        },
        "secure_request": {
          "description": "base64 encoded protocol.SecureRequest signed message",
          "type": "string",
          "format": "byte"
        }
      }
    }
  }
}`))
}