package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
)

// التحقق من التوقيع
func verifySignature(subDir, timestamp, providedSig string) bool {
	// استخدام secretKey الخاص بالخادم
	secret := os.Getenv("MEDIA_SERVER_SECRET")
	if secret == "" {
		log.Fatal("MEDIA_SERVER_SECRET not set")
	}

	// توليد التوقيع
	message := fmt.Sprintf("%s:%s", subDir, timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(providedSig), []byte(expectedSig))
}

// middleware للتحقق من التوقيع
func verifySignatureMiddleware(c *fiber.Ctx) error {
	subDir := c.FormValue("sub_dir")
	timestamp := c.FormValue("timestamp")
	signature := c.FormValue("signature")

	// تحقق من التوقيع
	if !verifySignature(subDir, timestamp, signature) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "توقيع غير صالح"})
	}

	// تحقق من صلاحية التاريخ (10 دقائق فقط)
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(t) > 10*time.Minute {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "انتهت صلاحية الرابط"})
	}

	// السماح بالمتابعة
	return c.Next()
}

// معالج رفع الملفات
func uploadHandler(c *fiber.Ctx) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "لم يتم استقبال الملف"})
	}

	// إنشاء المجلد إذا لم يكن موجود
	uploadPath := "./public/uploads"
	if err := os.MkdirAll(uploadPath, os.ModePerm); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "فشل في إنشاء المجلد"})
	}

	// حفظ الملف باسم عشوائي
	ext := filepath.Ext(file.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	fullPath := filepath.Join(uploadPath, filename)

	if err := c.SaveFile(file, fullPath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "فشل في حفظ الملف"})
	}

	fileURL := fmt.Sprintf("/images/%s", filename)
	return c.JSON(fiber.Map{
		"message":  "تم رفع الملف بنجاح ✅",
		"file_url": fileURL,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	app := fiber.New()

	// Middlewares
	app.Use(helmet.New())
	app.Use(blockMaliciousPaths)
	app.Use(blockBadUserAgents)
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "https://merketly.com", // انتبه لتعديل الرابط
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))
	app.Use(limiter.New(limiter.Config{
		Max:        60,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
	}))
	var suspiciousIPs = make(map[string]int)
	var ipMutex sync.Mutex
	app.Use(func(c *fiber.Ctx) error {
		ip := c.IP()
		// Check if path is suspicious
		if strings.Contains(c.Path(), ".php") || strings.Contains(c.Path(), "wp-") {
			ipMutex.Lock()
			suspiciousIPs[ip]++
			if suspiciousIPs[ip] > 5 { // After 5 suspicious requests
				ipMutex.Unlock()
				return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
			}
			ipMutex.Unlock()
		}
		return c.Next()
	})
	app.Use(func(c *fiber.Ctx) error {
		if strings.HasPrefix(c.Path(), "/images/") {
			c.Set("Access-Control-Allow-Origin", "*") // or "https://alfarestkd.com"
			c.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")
		}
		return c.Next()
	})
	app.Use(logger.New(logger.Config{
		Format: "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
		// Skip logging for common attack patterns
		Next: func(c *fiber.Ctx) bool {
			path := strings.ToLower(c.Path())
			return strings.Contains(path, ".php") ||
				strings.Contains(path, "wp-") ||
				strings.Contains(path, "admin")
		},
	}))
	// حماية جميع المسارات باستخدام middleware للتحقق من التوقيع
	app.Use(verifySignatureMiddleware)
	app.Options("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Static Serve
	app.Static("/images", "./public/uploads")

	// API endpoints
	app.Post("/upload", uploadHandler)
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("Media server is healthy ✅")
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	log.Fatal(app.ListenTLS(":"+port, "/etc/letsencrypt/live/media.merketly.com/fullchain.pem", "/etc/letsencrypt/live/media.merketly.com/privkey.pem"))
}
func blockMaliciousPaths(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodHead {
		// fmt.Printf("Blocked HEAD request from IP %s\n", c.IP())
		return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
	}
	method := c.Method()
	if method != fiber.MethodGet && method != fiber.MethodPost {
		return c.Next()
	}

	path := strings.ToLower(c.Path())

	// Fast block for .php and common variants
	if strings.HasSuffix(path, ".php") ||
		strings.Contains(path, ".php/") ||
		strings.Contains(path, ".php?") {
		// fmt.Printf("Blocked PHP path attempt: %s from IP %s\n", path, c.IP())
		return c.Status(fiber.StatusNotFound).SendString("404 Not Found")
	}
	// ✅ Allow safe static asset paths
	safePrefixes := []string{
		"/icons/", "/assets/", "/images/", "/flutter_", "/main.dart.js", "/index.html",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(path, prefix) {
			return c.Next()
		}
	}
	// List of known malicious path segments
	blockedPatterns := []string{
		"wp-", "wordpress", "xmlrpc", "wp-content", "wp-includes",
		".env", ".git", ".well-known", "phpmyadmin", "mysql", "cgi-bin",
		"vendor", "tmp", "upload", "backup", "shell", "wso", "r57", "b374k",
		"sym", "fox", "bypass", "exploit", "alfa", "mad", "ninja", "config",
	}

	for _, pattern := range blockedPatterns {
		if strings.Contains(path, pattern) {
			// fmt.Printf("Blocked malicious path attempt: %s from IP %s\n", path, c.IP())
			return c.Status(fiber.StatusNotFound).SendString("404 Not Found")
		}
	}

	return c.Next()
}
func blockBadUserAgents(c *fiber.Ctx) error {
	ua := strings.ToLower(c.Get("User-Agent"))

	badAgents := []string{
		"sqlmap", "curl", "wget", "python-requests", "nikto", "fuzzer",
		"scan", "spider", "bot", "hacker", "exploit", "security", "pen-test",
	}

	for _, bot := range badAgents {
		if strings.Contains(ua, bot) {
			// fmt.Printf("Blocked bad user agent: %s from IP %s", ua, c.IP())
			return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
		}
	}
	return c.Next()
}
