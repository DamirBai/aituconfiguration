package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

const (
	githubClientID     = "44bcdc0d0a62af72e21a"
	githubClientSecret = "13a929650298578771e37fc16a2c69eea082010e"
)

var oauthConfig = &oauth2.Config{
	ClientID:     githubClientID,
	ClientSecret: githubClientSecret,
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	},
	RedirectURL: "http://localhost:3000/auth/github/callback",
	Scopes:      []string{"user:email"},
}

var db *sql.DB
var store *sessions.CookieStore

func main() {
	r := mux.NewRouter()
	store = sessions.NewCookieStore([]byte("your-secret-key"))

	// Установка соединения с базой данных PostgreSQL
	connStr := "user=postgres password=admin dbname=assignmentgo4 sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}
	defer db.Close()

	// Проверка соединения с базой данных
	err = db.Ping()
	if err != nil {
		log.Fatal("Ошибка проверки подключения к базе данных:", err)
	}
	fmt.Println("Подключение к базе данных PostgreSQL установлено успешно!")

	// Создание таблицы пользователей, если её нет
	createUserTable := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password VARCHAR(100) NOT NULL,
		token VARCHAR(100) NOT NULL,
		confirmed BOOLEAN DEFAULT FALSE
	);
	`
	_, err = db.Exec(createUserTable)
	if err != nil {
		log.Fatal("Ошибка при создании таблицы пользователей:", err)
	}

	// Установка обработчиков маршрутов
	r.HandleFunc("/api/users/{id}", handleGetUser).Methods("GET")
	r.HandleFunc("/register", serveRegisterPage).Methods("POST")
	r.HandleFunc("/login", handleLogin).Methods("POST")
	r.HandleFunc("/auth/github/callback", handleGitHubCallback).Methods("GET")
	r.HandleFunc("/confirm.html", handleConfirmation).Methods("GET")
	r.HandleFunc("/index.html", serveIndexPage).Methods("GET")
	r.HandleFunc("/", serveRegisterPage).Methods("GET")
	r.HandleFunc("/api/users", handleUsers).Methods("GET")
	r.HandleFunc("/api/users/create", handleCreateUser).Methods("POST")
	r.HandleFunc("/confirm", handleConfirmation).Methods("POST")
	r.HandleFunc("/api/users/{id}/update", handleUpdateUser).Methods("PUT")
	r.HandleFunc("/api/users/{id}/delete", handleDeleteUser).Methods("DELETE")
	r.HandleFunc("/configurator.html", serveSimplePage("configurator.html")).Methods("GET")
	r.HandleFunc("/shops.html", serveSimplePage("shops.html")).Methods("GET")
	r.HandleFunc("/components.html", serveSimplePage("components.html")).Methods("GET")
	r.HandleFunc("/about.html", serveSimplePage("about.html")).Methods("GET")
	r.HandleFunc("/contact.html", serveSimplePage("contact.html")).Methods("GET")
	r.HandleFunc("/Videocards.html", serveSimplePage("Videocards.html")).Methods("GET")
	r.HandleFunc("/RAM.html", serveSimplePage("RAM.html")).Methods("GET")
	r.HandleFunc("/ROM.html", serveSimplePage("ROM.html")).Methods("GET")
	r.HandleFunc("/CPUs.html", serveSimplePage("CPUs.html")).Methods("GET")
	r.HandleFunc("/profile.html", serveSimplePage("profile.html")).Methods("GET")
	r.HandleFunc("/confirm.html", serveSimplePage("confirm.html")).Methods("GET")
	r.HandleFunc("/index.html", serveSimplePage("index.html")).Methods("GET")
	r.HandleFunc("/", serveSimplePage("register.html")).Methods("GET")

	// Запуск сервера на порту 3000
	server := &http.Server{
		Addr:         ":3000",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func serveSimplePage(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := ioutil.ReadFile(page)
		if err != nil {
			http.Error(w, fmt.Sprintf("Unable to read %s", page), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s", content)
	}
}

func exchangeCodeForToken(code string) (string, error) {
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func getUserInfo(token string) (*User, error) {
	// Создание HTTP клиента с токеном доступа
	httpClient := oauthConfig.Client(context.Background(), &oauth2.Token{AccessToken: token})

	// Получение данных о пользователе с помощью GitHub API
	resp, err := httpClient.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Парсинг ответа
	var user struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	// Возвращение информации о пользователе
	return &User{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}, nil
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	// Обмен кода авторизации на токен доступа
	token, err := exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Получение информации о пользователе с помощью токена доступа
	user, err := getUserInfo(token)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Проверка, есть ли пользователь уже в базе данных
	var existingEmail string
	err = db.QueryRow("SELECT email FROM users WHERE email = $1", user.Email).Scan(&existingEmail)
	if err == nil {
		// Если пользователь уже существует, перенаправляем на главную страницу
		http.Redirect(w, r, "/index.html", http.StatusSeeOther)
		return
	}

	// Если пользователь не найден в базе данных, добавляем его
	err = registerUser(user.Name, user.Email, []byte(""))
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Аутентификация пользователя
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	session.Values["authenticated"] = true
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Перенаправление на главную страницу
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Retrieve user from the database using the provided email
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Authentication successful, set session flag
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	session.Values["authenticated"] = true
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect or respond as needed
	http.Redirect(w, r, "/index.html", http.StatusSeeOther)
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	// Получение списка пользователей из базы данных
	rows, err := db.Query("SELECT id, name, email FROM users")
	if err != nil {
		http.Error(w, "Ошибка при получении списка пользователей", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email); err != nil {
			http.Error(w, "Ошибка при сканировании пользователей", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	json.NewEncoder(w).Encode(users)
}

func serveRegisterPage(w http.ResponseWriter, r *http.Request) {
	// Проверка, является ли запрос POST-запросом для регистрации
	if r.Method == "POST" {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Проверка, существует ли уже пользователь с таким же адресом электронной почты
		var existingEmail string
		err := db.QueryRow("SELECT email FROM users WHERE email = $1", email).Scan(&existingEmail)
		if err == nil {
			// Если пользователь с таким адресом электронной почты уже существует, возвращаем ошибку
			http.Error(w, "User with this email already exists", http.StatusBadRequest)
			return
		}

		// Хеширование пароля для безопасного хранения
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing the password", http.StatusInternalServerError)
			return
		}

		// Регистрация нового пользователя
		err = registerUser(name, email, hashedPassword)
		if err != nil {
			http.Error(w, "Error registering user", http.StatusInternalServerError)
			return
		}

		// Перенаправление на главную страницу после успешной регистрации
		http.Redirect(w, r, "/index.html", http.StatusSeeOther)
		return
	}

	// Если запрос GET, отдаем страницу регистрации
	content, err := ioutil.ReadFile("sign.html")
	if err != nil {
		http.Error(w, "Unable to read sign.html", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", content)
}

func serveIndexPage(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadFile("index.html")
	if err != nil {
		http.Error(w, "Unable to read index.html", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", content)
}

func registerUser(name, email string, password []byte) error {
	token := generateToken()
	_, err := db.Exec("INSERT INTO users (name, email, password, token) VALUES ($1, $2, $3, $4)", name, email, password, token)
	if err != nil {
		log.Println("Ошибка при регистрации пользователя в базе данных:", err)
		return err
	}

	err = sendConfirmationEmail(email, token)
	if err != nil {
		log.Println("Ошибка при отправке письма:", err)
	}

	return nil
}

func sendConfirmationEmail(email, token string) error {
	from := "sceletron45@gmail.com"
	password := "vohj pchs tknr jwrg"
	to := []string{email}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	message := []byte("Subject: Подтверждение регистрации\r\n" +
		"\r\n" +
		"Здравствуйте!\r\n" +
		"Для завершения регистрации нажмите на кнопку ниже:\r\n" +
		"<form action=\"http://localhost:3000/confirm\" method=\"POST\">" +
		"<input type=\"hidden\" name=\"token\" value=\"" + token + "\">" +
		"<button type=\"submit\">Подтвердить регистрацию</button>" +
		"</form>\r\n")
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Email Sent Successfully!")
	return nil
}

func handleConfirmation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Token not provided", http.StatusBadRequest)
		return
	}

	// Проверить наличие токена в базе данных и выполнить необходимые действия
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE token = $1", token).Scan(&email)
	if err != nil {
		http.Error(w, "Ошибка подтверждения регистрации", http.StatusBadRequest)
		return
	}

	// Обновить статус подтверждения пользователя в базе данных
	_, err = db.Exec("UPDATE users SET confirmed = true WHERE token = $1", token)
	if err != nil {
		http.Error(w, "Ошибка при обновлении статуса подтверждения пользователя", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Регистрация пользователя %s подтверждена успешно!", email)
}

func generateToken() string {
	// Генерация нового UUID (уникального идентификатора)
	token := uuid.New().String()
	return token
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Ошибка при декодировании данных пользователя", http.StatusBadRequest)
		return
	}

	token := generateToken()

	// Добавление нового пользователя в базу данных
	_, err := db.Exec("INSERT INTO users (name, email, password, token) VALUES ($1, $2, $3, $4)", newUser.Name, newUser.Email, newUser.Password, token)
	if err != nil {
		http.Error(w, "Ошибка при создании нового пользователя", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	// Получение ID пользователя из URL
	vars := mux.Vars(r)
	userID := vars["id"]

	// Поиск пользователя в базе данных по ID
	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		http.Error(w, "Ошибка при получении пользователя", http.StatusInternalServerError)
		return
	}

	// Отправка информации о пользователе в формате JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	// Получение ID пользователя из URL
	// Обновление информации о пользователе в базе данных
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	// Получение ID пользователя из URL
	// Удаление пользователя из базы данных
}

type User struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Token     string `json:"token"`
	Confirmed bool   `json:"confirmed"`
}
