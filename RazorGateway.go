package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"subscriptionapiv9/config"
	"time"

	"github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/charge"
	"github.com/stripe/stripe-go/checkout/session"
	"github.com/stripe/stripe-go/paymentintent"
)

type createCheckoutSessionResponse struct {
	SessionID string `json:"id"`
}

//	type RazorPay struct {
//		Amount          int    `json:"amount"`
//		Currency        string `json:"currency"`
//		Receipt         string `json:"receipt"`
//		Payment_capture bool   `json:"payment_capture"`
//	}
var RAZ_API_KEY string
var RAZ_SECRET_KEY string
var ENVIRONMENT string
var PGDATA map[string]interface{}

type Items struct {
	Name     string `json:"name"`
	Amount   int    `json:"amount"`
	Currenty string `json:"currency"`
}

type Add struct {
	Item Items `json:"item"`
}

type RazorPay struct {
	PlanId         string `json:"plan_id"`
	CustomerId     string `json:"customer_id"`
	CustomerNotify int    `json:"customer_notify"`
	TotalCount     int    `json:"total_count"`
	Quantity       int    `json:"quantity"`
	//Amount         int    `json:"amount"`
	//AddOns interface{} `json:"addons"`
	// StartAt        int    `json:"start_at"`
}

type PaymentRef struct {
	PymntRef string `json:"trans_id"`
}
type RazorPayOrder struct {
	Amount          int        `json:"amount"`
	Currency        string     `json:"currency"`
	Receipt         string     `json:"receipt"`
	Payment_capture int        `json:"payment_capture"`
	Notes           PaymentRef `json:"notes"`
}

type RazorPlan struct {
	Period         string `json:"period"`
	PeriodInterval int    `json:"interval"`
	Item           Item   `json:"item"`
}

type RazorAddon struct {
	Quantity       int    `json:"quantity"`
	SubscriptionId string `json:"-"`
	Item           Item   `json:"item"`
}

type Item struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Amount      int    `json:"amount"`
	Currency    string `json:"currency"`
}

type RazorResponse struct {
	Id          string `json:"id"`
	Entity      string `json:"entity"`
	Amount      int    `json:"amount"`
	Amount_paid int    `json:"amount_paid"`
	Amount_due  int    `json:"amount_due"`
	Currency    string `json:"currency"`
	Receipt     string `json:"receipt"`
	Offer_id    string `json:"offer_id"`
	Status      string `json:"status"`
	Attempts    int    `json:"attempts"`
	Notes       []string
	Created_at  int `json:"created_at"`
}

type RazorPlanResponse struct {
	Id       string `json:"id"`
	Entity   string `json:"entity"`
	Period   string `json:"period"`
	Interval int    `json:"interval"`
}

type RazorAddonResponse struct {
	Id             string `json:"id"`
	Entity         string `json:"entity"`
	SubscriptionId string `json:"subscription_id"`
	Quantity       int    `json:"quantity"`
}
type RazorCancel struct {
	CancelAtCycleEnd int `json:"cancel_at_cycle_end"`
}
type RazorPause struct {
	PauseAt string `json:"pause_at"`
}
type RazorResume struct {
	ResumeAt string `json:"resume_at"`
}
type RazorCancelResponse struct {
	Id             string `json:"id"`
	Entity         string `json:"entity"`
	SubscriptionId string `json:"subscription_id"`
	Quantity       int    `json:"quantity"`
}
type PaymentVal struct {
	ApiKey    string `json:"api_key"`
	SecretKey string `json:"secret_key"`
}
type PaymentsStr struct {
	Default  string     `json:"default"`
	RazorPay PaymentVal `json:"razorpay"`
	Stripe   PaymentVal `json:"stripe"`
}

func RazorPayAuth(token string) (error_code string, error_msg string, err error) {
	tokenData := PGDATA[token].(map[string]interface{})
	envData := tokenData[ENVIRONMENT].(map[string]interface{})

	var RAZ_API_KEY, RAZ_SECRET_KEY string
	RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	resp, err := http.Get("https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/payments")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR AUTH :", string(ResponseCode), err)
		return ResponseCode, "Authenticated Succesfully", err
	} else {
		log.Println("RZR AUTH ERR : ", string(body))
		return string(ResponseCode), string(body), err
	}
	return
}

func RazorVerifyChecksum(dataMap map[string]string, appID int64) (res string, err error) {
	var payload string
	var expectedSignature string
	// tokenData := PGDATA[token].(map[string]interface{})
	// envData := tokenData[ENVIRONMENT].(map[string]interface{})

	var RAZ_API_KEY, RAZ_SECRET_KEY string
	// RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	// RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	resout, err := GetPaymentsOpions(appID)
	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey
	log.Println("RAZ_API_KEY.... ", RAZ_API_KEY+"plGk")
	//log.Println(RAZ_API_KEY)
	razorpayOrderId := dataMap["razorpay_order_id"]
	razorpayPaymentId := dataMap["razorpay_payment_id"]
	razorpaySignature := dataMap["razorpay_signature"]

	payload = razorpayOrderId + "|" + razorpayPaymentId
	expectedSignature = ComputeHmac(payload, RAZ_SECRET_KEY)
	log.Println("payload:", payload)
	log.Println("expectedSignature:", expectedSignature)
	if expectedSignature == razorpaySignature {
		return "successs", err
	} else {
		return "failure", err
	}

	return
}

func RazorVerifySubsChecksum(dataMap map[string]string, token string) (res string) {
	var payload string
	var expectedSignature string
	razorpaySubscriptionId := dataMap["razorpay_subscription_id"]
	razorpayPaymentId := dataMap["razorpay_payment_id"]
	razorpaySignature := dataMap["razorpay_signature"]
	tokenData := PGDATA[token].(map[string]interface{})
	envData := tokenData[ENVIRONMENT].(map[string]interface{})

	var RAZ_API_KEY, RAZ_SECRET_KEY string
	RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	log.Println(RAZ_SECRET_KEY + "---" + RAZ_API_KEY + "---" + razorpaySubscriptionId + "--" + razorpayPaymentId + "---" + razorpaySignature)
	payload = razorpayPaymentId + "|" + razorpaySubscriptionId
	expectedSignature = ComputeHmac(payload, RAZ_SECRET_KEY)
	if expectedSignature == razorpaySignature {
		return "success"
	} else {
		return "failure"
	}
	return
}

func ComputeHmac256(payload string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func ComputeHmac(payload string, secret string) string {
	key := []byte(secret)
	pyload := []byte(payload)
	hash := hmac.New(sha256.New, key)
	hash.Write(pyload)
	// to lowercase hexits
	res := hex.EncodeToString(hash.Sum(nil))
	return res
	// to base64
	//return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func RazorCreateOrder(amount int, currency string, receipt string, payment_capture int, appID int64) (res *RazorResponse, error_code string, error_msg string, err error) {
	var APIURL string
	var RAZ_API_KEY, RAZ_SECRET_KEY string
	// tokenData := PGDATA[token].(map[string]interface{})
	// envData := tokenData[ENVIRONMENT].(map[string]interface{})
	// RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	// RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	resout, err := GetPaymentsOpions(appID)
	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey
	log.Println("RAZ_API_KEY.... ", RAZ_API_KEY+"plGk")
	rzrPAY := new(RazorPayOrder)
	rzrPAY.Amount = amount
	rzrPAY.Currency = currency
	rzrPAY.Receipt = receipt
	rzrPAY.Payment_capture = payment_capture
	//GateWayReff := time.Now().Format("20060102150405")
	rzrPAY.Notes.PymntRef = time.Now().Format("20060102150405")
	postJson, err := json.Marshal(rzrPAY)
	K := string(postJson)
	fmt.Println(K)
	postContent := bytes.NewBuffer(postJson)

	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/orders"
	log.Println(APIURL)
	resp, err := http.Post(APIURL, "application/json", postContent)
	//log.Println(resp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazRes = new(RazorResponse)
	body, err := ioutil.ReadAll(resp.Body)
	//log.Println("^^^^^^^^^^^^^^^^^^^ : ", string(body))
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Create vvvvvv :", string(body), err)
		err := json.Unmarshal(body, &RazRes)
		return RazRes, string(ResponseCode), "Order Created Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazRes, string(ResponseCode), string(body), err
	}
	// return
}
func RazorCreateOrder1(amount int, currency string, receipt string, payment_capture int, appID int64, orderid int) (res *RazorResponse, error_code string, error_msg string, err error) {
	var APIURL string
	var RAZ_API_KEY, RAZ_SECRET_KEY string
	resout, err := GetPaymentsOpions(appID)
	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey
	log.Println("RAZ_API_KEY.... ", RAZ_API_KEY+"plGk")
	rzrPAY := new(RazorPayOrder)
	rzrPAY.Amount = amount
	rzrPAY.Currency = currency
	rzrPAY.Receipt = receipt
	rzrPAY.Payment_capture = payment_capture
	//GateWayReff := time.Now().Format("20060102150405")
	rzrPAY.Notes.PymntRef = strconv.Itoa(orderid)
	postJson, err := json.Marshal(rzrPAY)
	K := string(postJson)
	fmt.Println(K)
	postContent := bytes.NewBuffer(postJson)

	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/orders"
	log.Println(APIURL)
	resp, err := http.Post(APIURL, "application/json", postContent)
	//log.Println(resp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazRes = new(RazorResponse)
	body, err := ioutil.ReadAll(resp.Body)
	//log.Println("^^^^^^^^^^^^^^^^^^^ : ", string(body))
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Create vvvvvv :", string(body), err)
		err := json.Unmarshal(body, &RazRes)
		return RazRes, string(ResponseCode), "Order Created Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazRes, string(ResponseCode), string(body), err
	}
	// return
}
func StripePayCreate(amount int, currency string, receipt string, payment_capture int, appID int64, stripeToken string) (string, error) {
	resout, err := GetPaymentsOpions(appID)
	log.Println("err", err)
	//S_API_KEY = resout.RazorPay.ApiKey
	stripe.Key = resout.Stripe.SecretKey
	amt := int64(amount)
	params := &stripe.ChargeParams{
		Amount:      stripe.Int64(amt),
		Currency:    stripe.String(string(stripe.CurrencyUSD)),
		Description: stripe.String(stripeToken),
		Shipping: &stripe.ShippingDetailsParams{
			Name: stripe.String("Subscriber"),
			Address: &stripe.AddressParams{
				Line1:      stripe.String("510 Townsend St"),
				PostalCode: stripe.String("98140"),
				City:       stripe.String("San Francisco"),
				State:      stripe.String("CA"),
				Country:    stripe.String("US"),
			},
		},
	}
	params.SetSource(stripeToken)

	ch, err := charge.New(params)
	//log.Println("ch, err", ch, err)
	transIDs := ""
	if err == nil {
		transIDs = ch.BalanceTransaction.ID
	}
	return transIDs, err
}

func StripePaymentIntent(amount int, currency string, appID int64) string {
	resout, err := GetPaymentsOpions(appID)
	log.Println("err", err)
	//S_API_KEY = resout.RazorPay.ApiKey
	stripe.Key = resout.Stripe.SecretKey
	amt := int64(amount)
	params := &stripe.PaymentIntentParams{

		Shipping: &stripe.ShippingDetailsParams{
			Name: stripe.String("Ritesh"),
			Address: &stripe.AddressParams{
				Line1:      stripe.String("510 Townsend St"),
				PostalCode: stripe.String("98140"),
				City:       stripe.String("San Francisco"),
				State:      stripe.String("CA"),
				Country:    stripe.String("US"),
			},
		},
		Description: stripe.String("Payment in process"),
		Amount:      stripe.Int64(amt),
		Currency:    stripe.String(currency),
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
	}
	pi, _ := paymentintent.New(params)
	fmt.Println("intent====", pi.ClientSecret)
	// clientScret :=pi.client_secret
	return pi.ClientSecret
}

func StripePayCreateOrder(Title, currency string, amount int, ptype, packagetype string, tp string) (string, error) {
	amt := int64(amount)
	var domain = ""
	// domain := "https://staging.multitvsolution.in/creator/index.html"
	// domain := "https://admin.creatorott.com/creator"
	if tp == "offer" {
		domain = "https://staging.multitvsolution.in/paynow.html"
	} else {
		domain = "https://cms-website.creatorott.com/#/completeorder"
	}
	if currency == "INR" {
		currency = "inr"
	} else if currency == "USD" {
		currency = "usd"
	}
	stripe.Key = STRIPE_SECRET

	// domain := "http://localhost/StripPay"
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			&stripe.CheckoutSessionLineItemParams{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String(string(currency)),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name: stripe.String(Title),
					},
					UnitAmount: stripe.Int64(amt),
				},
				Quantity: stripe.Int64(1),
			},
		},
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String(domain + "?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(domain + "?session_id="),
	}
	session, err := session.New(params)
	if err != nil {
		log.Printf("session.New: %v", err)
		return "", err
	}
	data := createCheckoutSessionResponse{
		SessionID: session.ID,
	}
	sesId := data.SessionID
	// js, _ := json.Marshal(data)
	// c.JSON(200, gin.H{"code": 1, "sessionId": sesId})
	//log.Println("data", sesId)
	return sesId, err
}

func RazorCreateSubscription(plan_id string, start_at int, subscription_length int, payment_capture int, token int64) (res *RazorResponse, error_code string, error_msg string, err error) {
	var APIURL string

	resout, err := GetPaymentsOpions(token)
	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey
	log.Println("RAZ_API_KEY.... ", RAZ_API_KEY+"")
	rzrPAY := new(RazorPay)

	rzrPAY.PlanId = plan_id 
	rzrPAY.Quantity = 1
	rzrPAY.TotalCount = 100
	rzrPAY.CustomerNotify = 1
	// rzrPAY.TotalCount = subscription_length
	// rzrPAY.AddOns = []interface{}{
	// 	map[string]interface{}{
	// 		"item": map[string]interface{}{
	// 			"name":     "Delivery charges",
	// 			"amount":   -800,
	// 			"currency": "INR",
	// 		},
	// 	},
	// }
	// log.Println(rzrPAY)
	// log.Println("----------------++", plan_id, start_at, payment_capture, subscription_length)
	postJson, err := json.Marshal(rzrPAY)
	postContent := bytes.NewBuffer(postJson)
	log.Println("===Environment", ENVIRONMENT)
	//tokenData := PGDATA[token].(map[string]interface{})
	//	log.Println(tokenData)
	//	envData := tokenData[ENVIRONMENT].(map[string]interface{})

	//var RAZ_API_KEY, RAZ_SECRET_KEY string
	//	RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	//	RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)

	//log.Println(customer_id)
	log.Println(subscription_length)
	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/subscriptions"
	//APIURL = "https://api.razorpay.com/v1/subscriptions"
	log.Println(APIURL)
	resp, err := http.Post(APIURL, "application/json", postContent)
	log.Println(rzrPAY)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazRes = new(RazorResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Create kkkkk :", string(body), err)
		err := json.Unmarshal(body, &RazRes)
		return RazRes, string(ResponseCode), "Order Credated Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazRes, string(ResponseCode), string(body), err
	}
	// return
}

func RazorCreatePlan(period string, period_interval int, name string, description string, amount int, currency string, token string) (res *RazorPlanResponse, error_code string, error_msg string, err error) {
	tokenData := PGDATA[token].(map[string]interface{})
	envData := tokenData[ENVIRONMENT].(map[string]interface{})

	var RAZ_API_KEY, RAZ_SECRET_KEY string
	RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	var APIURL string
	log.Println(RAZ_API_KEY + RAZ_SECRET_KEY)

	rzrPlan := new(RazorPlan)
	rzrPlan.Period = period
	rzrPlan.PeriodInterval = period_interval
	rzrPlan.Item.Name = name
	rzrPlan.Item.Description = description
	rzrPlan.Item.Amount = amount * 100
	rzrPlan.Item.Currency = currency

	postJson, err := json.Marshal(rzrPlan)
	postContent := bytes.NewBuffer(postJson)
	//log.Println(customer_id)
	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/plans"
	resp, err := http.Post(APIURL, "application/json", postContent)
	//log.Println(resp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazPlanRes = new(RazorPlanResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Create :", string(body), err)
		err := json.Unmarshal(body, &RazPlanRes)
		return RazPlanRes, string(ResponseCode), "Plan Created Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazPlanRes, string(ResponseCode), string(body), err
	}
	// return
}

func RazorCreateAddon(subscription_id string, name string, description string, amount int, currency string, token string) (res *RazorAddonResponse, error_code string, error_msg string, err error) {
	tokenData := PGDATA[token].(map[string]interface{})
	envData := tokenData[ENVIRONMENT].(map[string]interface{})

	var RAZ_API_KEY, RAZ_SECRET_KEY string
	RAZ_API_KEY = envData["RAZ_API_KEY"].(string)
	RAZ_SECRET_KEY = envData["RAZ_SECRET_KEY"].(string)
	var APIURL string
	log.Println(RAZ_API_KEY + RAZ_SECRET_KEY)

	rzrAddon := new(RazorAddon)
	rzrAddon.Quantity = 1
	//rzrAddon.SubscriptionId = subscription_id
	rzrAddon.Item.Name = name
	rzrAddon.Item.Description = description
	rzrAddon.Item.Amount = amount * 100
	rzrAddon.Item.Currency = currency

	postJson, err := json.Marshal(rzrAddon)
	postContent := bytes.NewBuffer(postJson)
	//log.Println(customer_id)
	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/subscriptions/" + subscription_id + "/addons"
	resp, err := http.Post(APIURL, "application/json", postContent)
	//log.Println(resp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazAddonRes = new(RazorAddonResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Createsssss :", string(body), err)
		err := json.Unmarshal(body, &RazAddonRes)
		return RazAddonRes, string(ResponseCode), "Plan Created Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazAddonRes, string(ResponseCode), string(body), err
	}
	return
}

func RazorCancelSubs(subscription_id string, token int64) (res *RazorCancelResponse, error_code string, error_msg string, err error) {
	// tokenData := PGDATA[token].(map[string]interface{})
	// envData := tokenData[ENVIRONMENT].(map[string]interface{})
	resout, err := GetPaymentsOpions(token)

	var RAZ_API_KEY, RAZ_SECRET_KEY string

	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey

	var APIURL string
	log.Println(RAZ_API_KEY + RAZ_SECRET_KEY)

	rzrCncel := new(RazorCancel)
	rzrCncel.CancelAtCycleEnd = 0
	postJson, err := json.Marshal(rzrCncel)
	postContent := bytes.NewBuffer(postJson)

	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/subscriptions/" + subscription_id + "/cancel"
	resp, err := http.Post(APIURL, "application/json", postContent)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazCancelRes = new(RazorCancelResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Createllll :", string(body), err)
		err := json.Unmarshal(body, &RazCancelRes)
		return RazCancelRes, string(ResponseCode), "Subscription  Cancelled  Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazCancelRes, string(ResponseCode), string(body), err
	}
	return
}
func RazorHoldSubs(subscription_id string, token int64) (res *RazorCancelResponse, error_code string, error_msg string, err error) {
	// tokenData := PGDATA[token].(map[string]interface{})
	// envData := tokenData[ENVIRONMENT].(map[string]interface{})
	resout, err := GetPaymentsOpions(token)

	var RAZ_API_KEY, RAZ_SECRET_KEY string

	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey

	var APIURL string
	log.Println(RAZ_API_KEY + RAZ_SECRET_KEY)

	rzrPause := new(RazorPause)
	rzrPause.PauseAt = "now"
	postJson, err := json.Marshal(rzrPause)
	postContent := bytes.NewBuffer(postJson)

	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/subscriptions/" + subscription_id + "/pause"
	resp, err := http.Post(APIURL, "application/json", postContent)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazCancelRes = new(RazorCancelResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	log.Println("------+++=________====", resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Createllll :", string(body), err)
		err := json.Unmarshal(body, &RazCancelRes)
		return RazCancelRes, string(ResponseCode), "Subscription  Cancelled  Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazCancelRes, string(ResponseCode), string(body), err
	}
	return
}
func RazorResumeSubs(subscription_id string, token int64) (res *RazorCancelResponse, error_code string, error_msg string, err error) {
	// tokenData := PGDATA[token].(map[string]interface{})
	// envData := tokenData[ENVIRONMENT].(map[string]interface{})
	resout, err := GetPaymentsOpions(token)

	var RAZ_API_KEY, RAZ_SECRET_KEY string

	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey

	var APIURL string
	log.Println(RAZ_API_KEY + RAZ_SECRET_KEY)

	rzrResume := new(RazorResume)
	rzrResume.ResumeAt = "now"
	postJson, err := json.Marshal(rzrResume)
	postContent := bytes.NewBuffer(postJson)

	APIURL = "https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/subscriptions/" + subscription_id + "/resume"
	resp, err := http.Post(APIURL, "application/json", postContent)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	var RazCancelRes = new(RazorCancelResponse)
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("RZR Order Createllll :", string(body), err)
		err := json.Unmarshal(body, &RazCancelRes)
		return RazCancelRes, string(ResponseCode), "Subscription  Cancelled  Successfully", err
	} else {
		log.Println("RZR Order Create ERR : ", string(body))
		return RazCancelRes, string(ResponseCode), string(body), err
	}
	return
}
func GetPaymentsOpions(AppID int64) (PaymentsStr, error) {
	log.Println("--------====", AppID)
	var values string
	var res PaymentsStr
	lquery := "SELECT  o.`value` FROM `users` as u Join options as o ON u.app_id = o.app_id where o.app_id=? and o.key ='PAYMENT_GATEWAY_KEYS'"
	log.Println(lquery, AppID)
	err := config.DB_READ.QueryRow(lquery, AppID).Scan(&values)
	if err != nil {
		log.Println("err", err)
		return res, err
	}
	json.Unmarshal([]byte(values), &res)

	return res, err
}

func RazorpayFetchPayment(paymentId string) (data string, err error) {
	var RAZ_API_KEY, RAZ_SECRET_KEY string

	resout, err := GetPaymentsOpions(1061)
	RAZ_API_KEY = resout.RazorPay.ApiKey
	RAZ_SECRET_KEY = resout.RazorPay.SecretKey
	resp, err := http.Get("https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/payments/" + paymentId)
	log.Println("https://" + RAZ_API_KEY + ":" + RAZ_SECRET_KEY + "@api.razorpay.com/v1/payments/" + paymentId)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var ResponseCode string
	body, err := ioutil.ReadAll(resp.Body)
	ResponseCode = strconv.Itoa(resp.StatusCode)

	data = string(body)
	//log.Println(data)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		log.Println("Payment_--------------------------DATAAAAAAAAAAAAAAA :", data, resp.StatusCode)
		return data, err
	} else {
		// log.Println("RZR AUTH ERR : ", string(body))
		log.Println(ResponseCode, "=====DDDDDDDDDDDDDDDDDDDDDDDDD====", resp.StatusCode)
		return "", err
	}

}
