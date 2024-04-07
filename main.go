package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	forwardUrl      string
	openIdConfigUrl string
	appid           string
	config          map[string]interface{}
	issueUrl        string
	tokenEndpoint   string
	redirectUrl     string
)

func init() {
	flag.StringVar(&appid, "appid", "", "app id for your sso")
	flag.StringVar(&forwardUrl, "forwardUrl", "", "the url of your application")
	flag.StringVar(&openIdConfigUrl, "openIdConfigUrl", "", "the url of your openid config, like https://xxxxx/webman/sso/.well-known/openid-configuration")
	flag.StringVar(&issueUrl, "issueUrl", "", "the url of your sso login page")
	flag.StringVar(&redirectUrl, "redirectUrl", "", "the url of your sso login successfully, should be the url of your this proxy running")

	flag.Parse()
	if appid == "" && os.Getenv("APP_ID") != "" {
		appid = os.Getenv("APP_ID")
	}
	if forwardUrl == "" && os.Getenv("FORWARD_URL") != "" {
		forwardUrl = os.Getenv("FORWARD_URL")
	}
	if openIdConfigUrl == "" && os.Getenv("OPENID_CONFIG_URL") != "" {
		openIdConfigUrl = os.Getenv("OPENID_CONFIG_URL")
	}
	if redirectUrl == "" && os.Getenv("REDIRECT_URL") != "" {
		redirectUrl = os.Getenv("REDIRECT_URL")
	}

	if appid == "" || forwardUrl == "" || openIdConfigUrl == "" || redirectUrl == "" {
		fmt.Println("appid, forwardUrl, openIdConfigUrl, redirectUrl is required")
		return
	}
	var err error
	config, err = getOpenIdConfig(openIdConfigUrl)
	if err != nil {
		panic(err)
	}

	issueUrl = config["authorization_endpoint"].(string)
	tokenEndpoint = config["token_endpoint"].(string)
}

func getOpenIdConfig(url string) (map[string]interface{}, error) {

	resp, err := http.Get(url)
	if err != nil {

		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {

		return nil, err
	}

	var config map[string]interface{}
	err = json.Unmarshal(body, &config)
	if err != nil {

		return nil, err
	}

	return config, nil
}

func TokenVerify(token string) (bool, error) {
	endpoint, _ := url.Parse(tokenEndpoint)
	if endpoint.Scheme == "http" {
		endpoint.Host = endpoint.Host + ":5000"
	}
	if endpoint.Scheme == "https" {
		endpoint.Host = endpoint.Host + ":5001"
	}
	finalUrl := fmt.Sprintf("%s://%s%s", endpoint.Scheme, endpoint.Host, endpoint.Path)
	urlWithParams := fmt.Sprintf("%s?action=exchange&app_id=%s&access_token=%s", finalUrl, appid, token)
	req, _ := http.NewRequest("GET", urlWithParams, nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err

	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err

	}
	responseBody := make(map[string]interface{})
	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		return false, err
	}

	if responseBody["success"] != true {
		return false, nil
	}
	return true, nil
}

func main() {

	http.HandleFunc("/sso-login", func(w http.ResponseWriter, r *http.Request) {
		//for safe, don't do this
		//host := r.Host
		//scheme := r.URL.Scheme
		//if scheme == "" {
		//	scheme = "http"
		//}
		//port := r.URL.Port()
		//if port != "" {
		//	port = ":" + port
		//}
		//requestUrl := fmt.Sprintf("%s://%s%s", scheme, host, port)

		redirectUrl := fmt.Sprintf("%s?app_id=%s&scope=user_id&synossoJSSDK=false&redirect_uri=%s", issueUrl, appid, redirectUrl)
		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
	})

	target, _ := url.Parse(forwardUrl)
	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Director = func(req *http.Request) {
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36")
		req.Header.Set("Referer", forwardUrl)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/sso-login") {
			cookie, _ := r.Cookie("synology-sso-access-token")
			if cookie != nil && cookie.Value != "" {
				tokenVerify, _ := TokenVerify(cookie.Value)
				if tokenVerify {
					proxy.ServeHTTP(w, r)
					return
				} else {
					http.SetCookie(w, &http.Cookie{
						Name:    "synology_sso_access_token",
						Value:   "",
						Expires: time.Unix(0, 0),
						Path:    "/",
					})
					http.Redirect(w, r, "/sso-login", http.StatusTemporaryRedirect)
				}
			}
			if cookie == nil {
				html := `<html><body><script>
             var accessToken = window.location.hash.split('&')[0].split('=')[1];
             if (accessToken) {
                 document.cookie = "synology-sso-access-token=" + accessToken;
                 window.location.href = '/';
             } else {
                 window.location.href = "/sso-login";
             }
            </script></body></html>`
				w.Write([]byte(html))
				return
			}
		} else {

			proxy.ServeHTTP(w, r)
		}
	})

	http.HandleFunc("/user-info", func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("synology-sso-access-token")
		if cookie != nil && cookie.Value != "" {
			endpoint, _ := url.Parse(tokenEndpoint)
			if endpoint.Scheme == "http" {
				endpoint.Host = endpoint.Host + ":5000"
			}
			if endpoint.Scheme == "https" {
				endpoint.Host = endpoint.Host + ":5001"
			}
			finalUrl := fmt.Sprintf("%s://%s%s", endpoint.Scheme, endpoint.Host, endpoint.Path)
			urlWithParams := fmt.Sprintf("%s?action=exchange&app_id=%s&access_token=%s", finalUrl, appid, cookie.Value)
			req, _ := http.NewRequest("GET", urlWithParams, nil)
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				w.WriteHeader(401)
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				w.WriteHeader(401)
				return

			}
			responseBody := make(map[string]interface{})
			err = json.Unmarshal(body, &responseBody)
			if err != nil {
				w.WriteHeader(401)
				return
			}

			if responseBody["success"] != true {
				w.WriteHeader(401)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(body)
			return
		} else {
			w.WriteHeader(401)
		}
	})

	fmt.Println("server is running on :10000")
	err := http.ListenAndServe(":10000", nil)
	if err != nil {
		return
	}
}
