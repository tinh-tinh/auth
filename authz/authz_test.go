package authz_test

import (
	"encoding/csv"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2/authz"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Test_Panic(t *testing.T) {
	require.Panics(t, func() {
		appModule := func() core.Module {
			return core.NewModule(core.NewModuleOptions{
				Imports: []core.Modules{authz.Register("./policy.csv", "./role.csv")},
			})
		}

		server := core.CreateFactory(appModule)
		server.PrepareBeforeListen()
	})

	appModule := core.NewModule(core.NewModuleOptions{})
	require.Nil(t, authz.Inject(appModule))
}

func guard(ref core.RefProvider, ctx core.Ctx) bool {
	enforcer := authz.Inject(ref)
	if enforcer == nil {
		log.Println("Enforcer is nil")
		return false
	}

	role := ctx.Query("role")
	if role == "" {
		log.Println("Role is empty")
		return false
	}

	res, err := enforcer.Enforce(role, ctx.Req().URL.Path, ctx.Req().Method)
	if err != nil {
		log.Println("Error enforcing policy:", err)
		return false
	}

	if !res {
		log.Printf("Access denied for role '%s' on path '%s' with method '%s'\n", role, ctx.Req().URL.Path, ctx.Req().Method)
		return false
	}

	log.Printf("Access granted for role '%s' on path '%s' with method '%s'\n", role, ctx.Req().URL.Path, ctx.Req().Method)
	return true
}

func appController(module core.Module) core.Controller {
	ctrl := module.NewController("")

	ctrl.Post("/login", func(ctx core.Ctx) error {
		return ctx.JSON(core.Map{
			"message": "Login successful",
		})
	})

	ctrl.Post("/logout", func(ctx core.Ctx) error {
		return ctx.JSON(core.Map{
			"message": "Logout successful",
		})
	})

	ctrl.Get("/member", func(ctx core.Ctx) error {
		return ctx.JSON(core.Map{
			"message": "Member area",
		})
	})

	return ctrl
}

func Test_Module(t *testing.T) {
	createFile()

	appModule := func() core.Module {
		return core.NewModule(core.NewModuleOptions{
			Imports:     []core.Modules{authz.Register("./model.conf", "./permissions.csv")},
			Controllers: []core.Controllers{appController},
			Guards:      []core.Guard{guard},
		})
	}
	server := core.CreateFactory(appModule)
	testServer := httptest.NewServer(server.PrepareBeforeListen())
	defer testServer.Close()

	testClient := testServer.Client()
	resp, err := testClient.Post(testServer.URL+"/login?role=anonymous", "application/json", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = testClient.Post(testServer.URL+"/logout?role=member", "application/json", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = testClient.Get(testServer.URL + "/member?role=admin")
	require.Nil(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp, err = testClient.Get(testServer.URL + "/member?role=anonymous")
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	deleteCsv()
}

func createFile() {
	// Define content
	model := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`

	// Create and write file
	err := os.WriteFile("model.conf", []byte(model), 0644)
	if err != nil {
		log.Fatalln("Failed to write model.conf:", err)
	}

	// Create or overwrite the file
	file, err := os.Create("permissions.csv")
	if err != nil {
		log.Fatalln("Error creating file:", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Data to write
	data := [][]string{
		{"p", "admin", "/*", "*"},
		{"p", "anonymous", "/login", "*"},
		{"p", "member", "/logout", "*"},
		{"p", "member", "/member/*", "*"},
	}

	// Write each record
	for _, record := range data {
		if err := writer.Write(record); err != nil {
			log.Fatalln("Error writing record:", err)
		}
	}
}

func deleteCsv() {
	err := os.Remove("permissions.csv")
	if err != nil {
		log.Println("Error deleting file:", err)
	} else {
		log.Println("File deleted successfully")
	}

	err = os.Remove("model.conf")
	if err != nil {
		log.Println("Error deleting model.conf:", err)
	} else {
		log.Println("Model file deleted successfully")
	}
}
