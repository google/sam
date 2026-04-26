// Copyright 2026 Google LLC
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

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
)

// FetchJWT fetches a JWT token using the Client Credentials flow.
func (n *SamNode) FetchJWT(ctx context.Context, tokenURL, clientID, clientSecret string) (string, error) {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	token, err := config.Token(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// InteractiveLogin prompts the user to go to a URL and paste the token back.
func (n *SamNode) InteractiveLogin(ctx context.Context, tokenURL string) (string, error) {
	fmt.Println("------------------------------------------------------------")
	fmt.Println("Device Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("To authenticate, please go to the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", tokenURL)
	fmt.Println("After successful login, copy the token and paste it below.")
	fmt.Println("------------------------------------------------------------")
	fmt.Print("Enter JWT Token: ")

	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read token: %v", err)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty token provided")
	}

	return token, nil
}
