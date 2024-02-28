package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var ACCESS_SECRET = []byte("alksjdhfghkfdjlsz")
var REFRESH_SECRET = []byte("utoewrtwoepirtyu")

type TokenPair struct {
	Access  string
	Refresh string
}

const PASSWORD = "XyDs8W2gpzgkj2eu"

var collection *mongo.Collection

func newAccessToken(id string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512,
		jwt.MapClaims{
			"sub": id,
			"exp": time.Now().Add(time.Minute * 20),
		})

	ret, _ := token.SignedString(ACCESS_SECRET)
	return ret
}

func newRefreshToken(id string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512,
		jwt.MapClaims{
			"sub": id,
			"iss": time.Now(),
			"exp": time.Now().Add(time.Hour * 24 * 10),
		})

	ret, err := token.SignedString(REFRESH_SECRET)

	if err != nil {
		panic(err)
	}

	return ret
}

func auth(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")

	// Тут должна быть какая-то аутентификация

	access := newAccessToken(guid)
	refresh := newRefreshToken(guid)

	remember(TokenPair{access, refresh})
	fmt.Println("AUTH: ", access, "\n REFRESH ", refresh)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenPair{access, refresh})
}

func refresh(w http.ResponseWriter, r *http.Request) {
	tp := TokenPair{}
	json.NewDecoder(r.Body).Decode(&tp)

	if !check(tp) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	access, _ := jwt.Parse(tp.Access, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ACCESS_SECRET, nil
	})

	// if err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	panic(err)
	// }

	// this should be refresh, _
	// _, _ = jwt.Parse(tp.Refresh, func(token *jwt.Token) (interface{}, error) {
	// 	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	// 		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	// 	}
	// 	return REFRESH_SECRET, nil
	// })

	// if err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }

	// the next bit is commented out for the sake of testing

	// if !refresh.Valid || access.Valid {
	// 	return //
	// }

	claims := access.Claims.(jwt.MapClaims)

	naccess := newAccessToken(claims["sub"].(string))
	nrefresh := newRefreshToken(claims["sub"].(string))

	collection.DeleteOne(
		context.TODO(),
		bson.D{{"access", tp.Access}},
	)

	remember(TokenPair{naccess, nrefresh})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenPair{naccess, nrefresh})
}

func remember(tp TokenPair) {
	signature := strings.Split(tp.Refresh, ".")[2]

	rhash, err := bcrypt.GenerateFromPassword(
		[]byte(signature[:72]),
		bcrypt.DefaultCost,
	)

	if err != nil {
		panic(err)
	}

	tp.Refresh = string(rhash)

	collection.InsertOne(context.TODO(), tp)
}

func check(tp TokenPair) bool {
	fromdb := TokenPair{}

	err := collection.
		FindOne(
			context.TODO(),
			bson.D{{"access", tp.Access}},
		).Decode(&fromdb)

	if err != nil {
		panic(err)
	}

	signature := strings.Split(tp.Refresh, ".")[2]
	err = bcrypt.CompareHashAndPassword(
		[]byte(fromdb.Refresh),
		[]byte(signature[:72]))
	return err == nil
}

func main() {
	clientOptions := options.Client().ApplyURI(
		fmt.Sprintf(
			"mongodb+srv://bkmz2000:%s@medos.wqtx959.mongodb.net/?retryWrites=true&w=majority&appName=medos", PASSWORD))

	client, err := mongo.Connect(context.TODO(), clientOptions)
	defer client.Disconnect(context.TODO())

	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	collection = client.
		Database("medos").
		Collection("acces_to_refresh")

	http.HandleFunc("/auth", auth)
	http.HandleFunc("/refresh", refresh)

	addr := "localhost:8080"
	fmt.Printf("Server listening on %s\n", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println(err)
	}
}
