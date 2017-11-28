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
	"log"

	"golang.org/x/net/context"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"firebase.google.com/go/ptr"

	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// [END admin_import]

// ==================================================================
// https://firebase.google.com/docs/admin/setup
// ==================================================================

func initializeAppWithServiceAccount() *firebase.App {
	// [START initialize_app_service_account]
	opt := option.WithCredentialsFile("path/to/serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}
	// [END initialize_app_service_account]

	return app
}

func initializeAppWithRefreshToken() *firebase.App {
	// [START initialize_app_refresh_token]
	opt := option.WithCredentialsFile("path/to/refreshToken.json")
	config := &firebase.Config{ProjectID: "my-project-id"}
	app, err := firebase.NewApp(context.Background(), config, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}
	// [END initialize_app_refresh_token]

	return app
}

func initializeAppDefault() *firebase.App {
	// [START initialize_app_default]
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}
	// [END initialize_app_default]

	return app
}

func accessServicesSingleApp() (*auth.Client, error) {
	// [START access_services_single_app]
	// Initialize default app
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	// Access auth service from the default app
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}
	// [END access_services_single_app]

	return client, err
}

func accessServicesMultipleApp() (*auth.Client, error) {
	// [START access_services_multiple_app]
	// Initialize the default app
	defaultApp, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	// Initialize another app with a different config
	opt := option.WithCredentialsFile("service-account-other.json")
	otherApp, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	// Access Auth service from default app
	defaultClient, err := defaultApp.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	// Access auth service from other app
	otherClient, err := otherApp.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}
	// [END access_services_multiple_app]
	// Avoid unused
	_ = defaultClient
	return otherClient, nil
}

// ==================================================================
// https://firebase.google.com/docs/auth/admin/create-custom-tokens
// ==================================================================

func createCustomToken(app *firebase.App) string {
	// [START create_custom_token]
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.CustomToken("some-uid")
	if err != nil {
		log.Fatalf("error minting custom token: %v\n", err)
	}

	log.Printf("Got custom token: %v\n", token)
	// [END create_custom_token]

	return token
}

func createCustomTokenWithClaims(app *firebase.App) string {
	// [START create_custom_token_claims]
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	claims := map[string]interface{}{
		"premiumAccount": true,
	}

	token, err := client.CustomTokenWithClaims("some-uid", claims)
	if err != nil {
		log.Fatalf("error minting custom token: %v\n", err)
	}

	log.Printf("Got custom token: %v\n", token)
	// [END create_custom_token_claims]

	return token
}

// ==================================================================
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
// ==================================================================

func verifyIDToken(app *firebase.App, idToken string) *auth.Token {
	// [START verify_id_token]
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(idToken)
	if err != nil {
		log.Fatalf("error verifying ID token: %v\n", err)
	}

	log.Printf("Verified ID token: %v\n", token)
	// [END verify_id_token]

	return token
}

// ==================================================================
// https://firebase.google.com/docs/auth/admin/manage-users
// ==================================================================

func getUser(ctx context.Context, client *auth.Client) *auth.UserRecord {
	uid := "some_string_uid"

	// [START get_user]
	u, err := client.GetUser(ctx, uid)
	if err != nil {
		log.Fatalf("error getting user %s: %v\n", uid, err)
	}
	log.Printf("Successfully fetched user data: %v\n", u)
	// [END get_user]
	return u
}

func getUserByEmail(ctx context.Context, client *auth.Client) *auth.UserRecord {
	email := "some@email.com"
	// [START get_user_by_email]
	u, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		log.Fatalf("error getting user by email %s: %v\n", email, err)
	}
	log.Printf("Successfully fetched user data: %v\n", u)
	// [END get_user_by_email]
	return u
}

func getUserByPhone(ctx context.Context, client *auth.Client) *auth.UserRecord {
	phone := "+13214567890"
	// [START get_user_by_phone]
	u, err := client.GetUserByPhoneNumber(ctx, phone)
	if err != nil {
		log.Fatalf("error getting user by phone %s: %v\n", phone, err)
	}
	log.Printf("Successfully fetched user data: %v\n", u)
	// [END get_user_by_phone]
	return u
}

func createUser(ctx context.Context, client *auth.Client) *auth.UserRecord {
	// [START create_user]
	u, err := client.CreateUser(context.Background(),
		&auth.UserParams{
			Email:         ptr.String("user@example.com"),
			EmailVerified: ptr.Bool(false),
			PhoneNumber:   ptr.String("+15555550100"),
			Password:      ptr.String("secretPassword"),
			DisplayName:   ptr.String("John Doe"),
			PhotoURL:      ptr.String("http://www.example.com/12345678/photo.png"),
			Disabled:      ptr.Bool(false),
		})
	if err != nil {
		log.Fatalf("error creating user: %v\n", err)
	}
	log.Printf("Successfully created user: %v\n", u)
	// [END create_user]
	return u
}

func createUserWUID(ctx context.Context, client *auth.Client) *auth.UserRecord {
	uid := "something"
	// [START create_user_with_uid]
	u, err := client.CreateUser(context.Background(),
		&auth.UserParams{UID: ptr.String(uid), Email: ptr.String("user@example.com"), PhoneNumber: ptr.String("+15555550100")})
	if err != nil {
		log.Fatalf("error creating user: %v\n", err)
	}
	log.Printf("Successfully created user: %v\n", u)
	// [END create_user_with_uid]
	return u
}

func updateUser(ctx context.Context, client *auth.Client) *auth.UserRecord {
	uid := "d"
	// [START update_user]
	u, err := client.UpdateUser(context.Background(), uid,
		&auth.UserParams{
			Email:         ptr.String("user@example.com"),
			EmailVerified: ptr.Bool(true),
			PhoneNumber:   ptr.String("+15555550100"),
			Password:      ptr.String("newPassword"),
			DisplayName:   ptr.String("John Doe"),
			PhotoURL:      ptr.String("http://www.example.com/12345678/photo.png"),
			Disabled:      ptr.Bool(true),
		})
	if err != nil {
		log.Fatalf("error updating user: %v\n", err)
	}
	log.Printf("Successfully updated user: %v\n", u)
	// [END update_user]
	return u
}

func deleteUser(ctx context.Context, client *auth.Client) {
	uid := "d"
	// [START delete_user]
	err := client.DeleteUser(context.Background(), uid)
	if err != nil {
		log.Fatalf("error deleting user: %v\n", err)
	}
	log.Printf("Successfully deleted user: %s\n", uid)
	// [END delete_user]
}

func listUsers(ctx context.Context, client *auth.Client) {
	// [START list_users]
	iter := client.Users(context.Background(), "")
loop:
	for {
		user, err := iter.Next()
		switch err {
		case nil:
			log.Printf("read user user: %v\n", user)
		case iterator.Done: // this is a special error value.
			break loop
		default:
			log.Fatalf("error listing users: %s\n", err)
		}
	}

	// Iterating by pages 7 users at a time
	iter2 := client.Users(context.Background(), "")
	pager := iterator.NewPager(iter2, 7, "")
	for {
		var users []*auth.ExportedUserRecord
		nextPageToken, err := pager.NextPage(&users)
		if err != nil {
			log.Fatalf("paging error %v", err)
		}
		for _, u := range users {
			log.Printf("read user user: %v\n", u)
		}
		if nextPageToken == "" {
			break
		}
	}
	// [END list_users]
}

// ==================================================================
// https://firebase.google.com/docs/storage/admin/start
// ==================================================================

func cloudStorage() {
	// [START cloud_storage]
	config := &firebase.Config{
		StorageBucket: "<BUCKET_NAME>.appspot.com",
	}
	opt := option.WithCredentialsFile("path/to/serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), config, opt)
	if err != nil {
		log.Fatalln(err)
	}

	client, err := app.Storage(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	bucket, err := client.DefaultBucket()
	if err != nil {
		log.Fatalln(err)
	}
	// 'bucket' is an object defined in the cloud.google.com/go/storage package.
	// See https://godoc.org/cloud.google.com/go/storage#BucketHandle
	// for more details.
	// [END cloud_storage]

	log.Printf("Created bucket handle: %v\n", bucket)
}

func cloudStorageCustomBucket(app *firebase.App) {
	client, err := app.Storage(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	// [START cloud_storage_custom_bucket]
	bucket, err := client.Bucket("my-custom-bucket")
	// [END cloud_storage_custom_bucket]
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Created bucket handle: %v\n", bucket)
}

func main() {
	app := initializeAppWithServiceAccount()

	_ = createCustomToken(app)
	_ = createCustomTokenWithClaims(app)
	_ = verifyIDToken(app, "some-token")
	cloudStorage()
	cloudStorageCustomBucket(app)
}
