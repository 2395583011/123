package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"database/sql"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

// User结构体表示用户信息
type User struct {
	Username  string `form:"username"`
	Password  string `form:"password"`
	UserLevel int    `form:"userlevel"`
	RealName  string `form:"realname"`
	Class     string `form:"class"`
	Gender    string `form:"gender"`
	RegDate   string `form:"regdate"`
}

// 数据库连接信息
const (
	Server   = "172.16.150.55"
	Port     = 1433
	Database = "web_test"
)

// 获取数据库连接字符串
func getConnectionString() string {
	return fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s;encrypt=disable",
		Server, "sa", "dbclass2023", Port, Database)
}

// 匹配登录信息
func checkCredentials(username string, password string) error {
	connString := getConnectionString()
	db, err := sql.Open("mssql", connString)
	if err != nil {
		return err
	}
	defer db.Close()

	var id int

	hash := md5.New()
	hash.Write([]byte(password))
	hashedPassword := hex.EncodeToString(hash.Sum(nil))

	err = db.QueryRow("SELECT id FROM userTable WHERE username = ? AND password = ?",
		username, hashedPassword).Scan(&id)

	if err == sql.ErrNoRows {
		return errors.New("错误的用户名或密码")
	} else if err != nil {
		return err
	}
	return nil
}

// 写入注册信息到数据库
func registerUser(user User) error {
	connString := getConnectionString()
	db, err := sql.Open("mssql", connString)
	if err != nil {
		return err
	}
	defer db.Close()

	// 检测用户名是否唯一
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM userTable WHERE username = ?", user.Username).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("用户名已存在")
	} else {

		stmt, err := db.Prepare("INSERT INTO userTable " +
			" (username, password, userlevel, truename, userclass, sex, regDate) VALUES (?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			return err
		}
		defer stmt.Close()

		// Get the current date and time
		now := time.Now()
		dateStr := now.Format("2006-01-02 15:04")
		user.RegDate = dateStr

		// Hash the password using MD5
		hash := md5.New()
		hash.Write([]byte(user.Password))
		hashedPassword := hex.EncodeToString(hash.Sum(nil))

		_, err = stmt.Exec(user.Username, hashedPassword, user.UserLevel, user.RealName, user.Class, user.Gender, user.RegDate)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	r := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	// 注册模板函数
	r.SetFuncMap(template.FuncMap{
		"safehtml": func(html string) template.HTML {
			return template.HTML(html)
		},
	})

	// 加载模板文件
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// 处理/login路径
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "loginNew.tmpl", gin.H{})
	})

	r.POST("/login", func(c *gin.Context) {
		// 获取表单数据
		username := c.PostForm("username")
		password := c.PostForm("password")

		// TODO: 验证用户登录信息，比如查询数据库或者验证密码是否正确
		err := checkCredentials(username, password)
		if err == nil {
			// 存储用户名到session
			session := sessions.Default(c)
			session.Set("username", username)
			session.Save()

			c.Redirect(http.StatusMovedPermanently, "/welcome")
		} else {
			c.HTML(http.StatusOK, "loginNew.tmpl", gin.H{
				"error": "错误的用户名或密码",
			})
		}
	})

	r.GET("/welcome", func(c *gin.Context) {

		session := sessions.Default(c)
		username := session.Get("username")

		if username != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"username": username,
			})
		} else {
			c.String(http.StatusUnauthorized, "你未被授权访问该页面")
		}

	})

	r.GET("/userlists", func(c *gin.Context) {

		session := sessions.Default(c)
		username := session.Get("username")

		if username == "admin" {

			connString := getConnectionString()
			db, err := sql.Open("mssql", connString)
			if err != nil {
				return
			}
			defer db.Close()

			sqlStr := "select username,password,userLevel,userclass,sex,regDate  from userTable order by id asc"
			rows, err := db.Query(sqlStr)
			if err != nil {
				log.Fatal("查询数据库failed:", err.Error())
			}
			defer rows.Close()

			infos := []User{}

			for rows.Next() {
				var info User

				err = rows.Scan(&info.Username, &info.Password, &info.UserLevel, &info.Class, &info.Gender,
					&info.RegDate)
				if err != nil {
					log.Fatal(err)
				}
				infos = append(infos, info)
			}

			c.HTML(http.StatusOK, "userlists.tmpl", gin.H{
				"username": username,
				"users":    infos,
			})
		} else {
			c.String(http.StatusUnauthorized, "你未被授权访问该页面")
		}

	})

	// 展示用户注册页面
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "regNew.tmpl", gin.H{})
	})

	// 处理用户提交的注册信息
	r.POST("/register", func(c *gin.Context) {
		var user User
		if err := c.ShouldBind(&user); err != nil {
			c.HTML(http.StatusBadRequest, "regNew.tmpl", gin.H{"error": "错误的字段数据"})
			return
		}

		// 注册用户
		if err := registerUser(user); err != nil {
			c.HTML(http.StatusInternalServerError, "regNew.tmpl", gin.H{"error": err.Error()})
			return
		}

		c.HTML(http.StatusOK, "regNew.tmpl", gin.H{"success": "注册成功"})
	})

	// 处理上传文件post
	r.POST("/upload", func(c *gin.Context) {
		file, _, err := c.Request.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("file err : %s", err.Error()))
			return
		}
		defer file.Close()

		fileContent, err := io.ReadAll(file)
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("file err : %s", err.Error()))
			return
		}

		username := c.PostForm("username")
		filename := c.PostForm("filename")
		uploadDate := time.Now()

		connString := getConnectionString()
		db, err := sql.Open("mssql", connString)
		if err != nil {
			return
		}
		defer db.Close()

		_, err = db.Exec("INSERT INTO userUpload (username, fileName, uploadFile, uploadDate) VALUES (?, ?, ?, ?)", username, filename, fileContent, uploadDate)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("database error: %s", err.Error()))
			return
		}

		c.String(http.StatusOK, fmt.Sprintf("文件 %s 上传成功,用户 = %s, 上传时间 = %s.", filename, username, uploadDate))
	})

	r.Run(":8080")
}
