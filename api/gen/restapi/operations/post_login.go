// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// PostLoginHandlerFunc turns a function with the right signature into a post login handler
type PostLoginHandlerFunc func(PostLoginParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostLoginHandlerFunc) Handle(params PostLoginParams) middleware.Responder {
	return fn(params)
}

// PostLoginHandler interface for that can handle valid post login params
type PostLoginHandler interface {
	Handle(PostLoginParams) middleware.Responder
}

// NewPostLogin creates a new http.Handler for the post login operation
func NewPostLogin(ctx *middleware.Context, handler PostLoginHandler) *PostLogin {
	return &PostLogin{Context: ctx, Handler: handler}
}

/*
	PostLogin swagger:route POST /login postLogin

# Logs into the service using auth0

Logs into the choria service
*/
type PostLogin struct {
	Context *middleware.Context
	Handler PostLoginHandler
}

func (o *PostLogin) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewPostLoginParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
