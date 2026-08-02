package tests

import (
	"fmt"
	"github.com/wendy512/go-iecp5/asdu"
	"github.com/rulego/rulego-components-iot/third_party/iec104/client"
	"github.com/rulego/rulego-components-iot/third_party/iec104/server"
	"sync"
	"testing"
	"time"
)

var once sync.Once

func TestClient(t *testing.T) {
	srv := startServer()
	settings := client.NewSettings()
	settings.LogCfg = &client.LogCfg{Enable: true}
	c := client.New(settings, &clientCall{})

	wg := sync.WaitGroup{}
	wg.Add(1)
	c.SetOnConnectHandler(func(c *client.Client) {
// Operation after successful connection
		fmt.Printf("connected %s iec104 server\n", settings.Host)
	})

	// Callback after server active confirmation
	c.SetServerActiveHandler(func(c *client.Client) {
		//// Send total call
		if err := c.SendInterrogationCmd(commonAddr); err != nil {
			t.Errorf("send interrogation cmd error %v\n", err)
			t.FailNow()
		}

// Cumulative interrogation
		if err := c.SendCounterInterrogationCmd(commonAddr); err != nil {
			t.Errorf("send counter interrogation cmd error %v\n", err)
			t.FailNow()
		}

		// read cmd
		if err := c.SendReadCmd(commonAddr, 100); err != nil {
			t.Errorf("send counter interrogation cmd error %v\n", err)
			t.FailNow()
		}

// Clock synchronization
		if err := c.SendClockSynchronizationCmd(commonAddr, time.Now()); err != nil {
			t.Errorf("send clock sync cmd error %v\n", err)
			t.FailNow()
		}

		// test cmd
		if err := c.SendTestCmd(commonAddr); err != nil {
			t.Errorf("send test cmd error %v\n", err)
			t.FailNow()
		}

// Single point control
		if err := c.SendCmd(commonAddr, asdu.C_SC_NA_1, asdu.InfoObjAddr(1000), false); err != nil {
			t.Errorf("send single cmd error %v\n", err)
			t.FailNow()
		}

// Test wait for reply, cannot finish too quickly
		time.Sleep(time.Second * 15)
		wg.Done()
	})

	// Sends server active after Connect
	if err := c.Connect(); err != nil {
		t.Errorf("client connect error %v\n", err)
		t.FailNow()
	}
	wg.Wait()

	if err := c.Close(); err != nil {
		t.Errorf("close error %v\n", err)
		t.FailNow()
	}
	srv.Stop()
}

func startServer() *server.Server {
	s := server.New(server.NewSettings(), &myServerHandler{})
	s.Start()
	time.Sleep(500 * time.Millisecond) // let listener bind; -race slows startup
	return s
}
