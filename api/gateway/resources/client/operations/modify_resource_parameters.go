// Code generated by go-swagger; DO NOT EDIT.

package operations

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	strfmt "github.com/go-openapi/strfmt"

	models "github.com/panther-labs/panther/api/gateway/resources/models"
)

// NewModifyResourceParams creates a new ModifyResourceParams object
// with the default values initialized.
func NewModifyResourceParams() *ModifyResourceParams {
	var ()
	return &ModifyResourceParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewModifyResourceParamsWithTimeout creates a new ModifyResourceParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewModifyResourceParamsWithTimeout(timeout time.Duration) *ModifyResourceParams {
	var ()
	return &ModifyResourceParams{

		timeout: timeout,
	}
}

// NewModifyResourceParamsWithContext creates a new ModifyResourceParams object
// with the default values initialized, and the ability to set a context for a request
func NewModifyResourceParamsWithContext(ctx context.Context) *ModifyResourceParams {
	var ()
	return &ModifyResourceParams{

		Context: ctx,
	}
}

// NewModifyResourceParamsWithHTTPClient creates a new ModifyResourceParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewModifyResourceParamsWithHTTPClient(client *http.Client) *ModifyResourceParams {
	var ()
	return &ModifyResourceParams{
		HTTPClient: client,
	}
}

/*ModifyResourceParams contains all the parameters to send to the API endpoint
for the modify resource operation typically these are written to a http.Request
*/
type ModifyResourceParams struct {

	/*Body*/
	Body *models.ModifyResource

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the modify resource params
func (o *ModifyResourceParams) WithTimeout(timeout time.Duration) *ModifyResourceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the modify resource params
func (o *ModifyResourceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the modify resource params
func (o *ModifyResourceParams) WithContext(ctx context.Context) *ModifyResourceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the modify resource params
func (o *ModifyResourceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the modify resource params
func (o *ModifyResourceParams) WithHTTPClient(client *http.Client) *ModifyResourceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the modify resource params
func (o *ModifyResourceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the modify resource params
func (o *ModifyResourceParams) WithBody(body *models.ModifyResource) *ModifyResourceParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the modify resource params
func (o *ModifyResourceParams) SetBody(body *models.ModifyResource) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ModifyResourceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
