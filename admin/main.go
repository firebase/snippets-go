// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// [START admin_import]
import (
	"fmt"

	"golang.org/x/net/context"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"

	"google.golang.org/api/option"
)

// [END admin_import]

// ==================================================================
// https://firebase.google.com/docs/admin/setup
// ==================================================================

func initializeAppWithServiceAccount() (*firebase.App, error) {
	// [START initialize_app_service_account]
	opt := option.WithCredentialsFile("path/to/serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}
	// [END initialize_app_service_account]

	return app, nil
}

func initializeAppWithRefreshToken() (*firebase.App, error) {
	// [START initialize_app_refresh_token]
	opt := option.WithCredentialsFile("path/to/refreshToken.json")
	config := &firebase.Config{ProjectID: "my-project-id"}
	app, err := firebase.NewApp(context.Background(), config, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}
	// [END initialize_app_refresh_token]

	return app, nil
}

func initializeAppDefault() (*firebase.App, error) {
	// [START initialize_app_default]
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}
	// [END initialize_app_default]

	return app, nil
}

func accessServicesSingleApp() (*auth.Client, error) {
	// [START access_services_single_app]
	// Initialize default app
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}

	// Access auth service from the default app
	client, err := app.Auth()
	if err != nil {
		return nil, fmt.Errorf("error getting Auth client: %v", err)
	}
	// [END access_services_single_app]

	return client, err
}

func accessServicesMultipleApp() (*auth.Client, error) {
	// [START access_services_multiple_app]
	// Initialize the default app
	defaultApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}

	// Initialize another app with a different config
	opt := option.WithCredentialsFile("service-account-other.json")
	otherApp, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}

	// Access Auth service from default app
	defaultClient, err := defaultApp.Auth()
	if err != nil {
		return nil, fmt.Errorf("error getting Auth client: %v", err)
	}

	// Access auth service from other app
	otherClient, err := otherApp.Auth()
	if err != nil {
		return nil, fmt.Errorf("error getting Auth client: %v", err)
	}
	// [END access_services_multiple_app]

	// Avoid unused
	_ = defaultClient
	return otherClient, nil
}

// ==================================================================
// https://firebase.google.com/docs/auth/admin/create-custom-tokens
// ==================================================================

func createCustomToken(app *firebase.App) (string, error) {
	// [START create_custom_token]
	client, err := app.Auth()
	if err != nil {
		return "", fmt.Errorf("error getting Auth client: %v", err)
	}

	token, err := client.CustomToken("some-uid")
	if err != nil {
		return "", fmt.Errorf("error minting custom token: %v", err)
	}

	fmt.Printf("Got custom token: %v\n", token)
	// [END create_custom_token]

	return token, nil
}

func createCustomTokenWithClaims(app *firebase.App) (string, error) {
	// [START create_custom_token_claims]
	client, err := app.Auth()
	if err != nil {
		return "", fmt.Errorf("error getting Auth client: %v", err)
	}

	claims := map[string]interface{}{
		"premiumAccount": true,
	}

	token, err := client.CustomTokenWithClaims("some-uid", claims)
	if err != nil {
		return "", fmt.Errorf("error minting custom token: %v", err)
	}

	fmt.Printf("Got custom token: %v\n", token)
	// [END create_custom_token_claims]

	return token, nil
}

// ==================================================================
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
// ==================================================================

func verifyIDToken(app *firebase.App, idToken string) (*auth.Token, error) {
	// [START verify_id_token]
	client, err := app.Auth()
	if err != nil {
		return nil, fmt.Errorf("error getting Auth client: %v", err)
	}

	token, err := client.VerifyIDToken(idToken)
	if err != nil {
		return nil, fmt.Errorf("error verifying ID token: %v", err)
	}

	fmt.Printf("Verified ID token: %v\n", token)
	// [END verify_id_token]

	return token, nil
}

func main() {
	app, err := initializeAppWithServiceAccount()
	if err != nil {
		fmt.Printf("error initializing app: %v\n", err)
		return
	}

	_, err = createCustomToken(app)
	if err != nil {
		fmt.Printf("Error in createCustomToken: %v\n", err)
	}

	_, err = createCustomTokenWithClaims(app)
	if err != nil {
		fmt.Printf("Error in createCustomTokenWithClaims: %v\n", err)
	}

	_, err = verifyIDToken(app, "some-token")
	if err != nil {
		fmt.Printf("Error in verifyIDToken: %v\n", err)
	}
}
