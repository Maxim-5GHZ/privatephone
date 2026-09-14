package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"privatephone/server/internal/api"
	"privatephone/server/internal/ca"
	"privatephone/server/internal/config"
	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[pp] ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "verify-journal":
		cmdVerifyJournal(os.Args[2:])
	case "journal-export":
		cmdJournalExport(os.Args[2:])
	case "journal-import":
		cmdJournalImport(os.Args[2:])
	case "vault-backup":
		cmdVaultBackup(os.Args[2:])
	case "vault-restore":
		cmdVaultRestore(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

const version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `privatephone ПАК АСК %s

usage:
  pp init [-data DIR] [-key PATH] [-rescue-out FILE] [-admin-out PATH] [-ips 192.168.1.10,..] [-no-tls] [-node NAME]
      первичное развёртывание: создаёт составной мастер-ключ (локальная половина
      data/pp.local + USB-половина pp.key на флешке), базу, ключ администратора,
      внутренний CA (data/ca.crt) и TLS-сертификат узла от этого CA для HTTPS/WSS
      (IP — через -ips). Корень CA импортируется в доверенные один раз на все
      абонентские устройства; -no-tls пропускает генерацию сертификатов.
      Флешка — носитель ключа: сервер сам находит/предлагает её и просит
      подтвердить выбор; конкурирующие флешки ДРУГИХ узлов не предлагаются и
      перечисляются с их именами. -key PATH — явный полный ключ (резервный
      сценарий); -rescue-out FILE сохраняет полный ключ в указанный файл (в сейф).
      -node NAME — короткое имя узла («ТАНЖЕР»), пишется в обе половины и на
      этикетку флешке; без него — автоген node-<hex>.
      По умолчанию -data — папка data РЯДОМ с бинарником (бинарник живёт в
      user-директории оператора, флешка несёт только половину ключа).

  pp run [-port :8080] [-data DIR] [-key PATH] [-watch] [-persist 5s] [-tls] [-node NAME]
      запуск узла связи. При извлечении USB-флешки — носителя ключа — процесс
      немедленно завершается, ключ из памяти затирается. -tls — слушать
      HTTPS/WSS (нужен WebRTC-звонкам и доступу по IP).
      Без -key — "мастер первого запуска": ключ собирается из половин
      (data/pp.local + найденная флешка с pp.key того же узла, выбор подтверждается),
      при отсутствии данных node сам себя инициализирует (vault, админ, CA,
      TLS) и стартует по https. -node задаёт имя узла для первого запуска.
      -key — явный полный ключ (резервный режим).

  pp verify-journal [-data DIR] [-key PATH]
      проверка целостности tamper-evident журнала: пересчитывает цепь хэшей
      и сообщает первый повреждённый пакет (exit 1 при повреждении).
      -key — полный ключ (резервный режим); без него ключ собирается из половин.

  pp journal-export [-data DIR] [-key PATH] [-after TS] [-out FILE]
      выгрузка журнала узла в «мешок» для sneaker-net-переноса (stdout, если -out '-').
      -after TS — только пакеты с ts >= TS (инкрементальный перенос).

  pp journal-import [-data DIR] [-key PATH] -in FILE
      импорт мешка на узел: проверяет подписи по локальному реестру абонентов,
      цепь хэшей и непрерывность с локальным журналом, затем воспроизводит
      события (метки, сообщения, тревоги, зоны, отзывы). Повторный импорт идемпотентен.

  pp vault-backup [-data DIR] [-key PATH] -out FILE
      упаковка зашифрованного vault.db (+ tls.crt/tls.key и admin.pem, если есть)
      в tar.gz-архив. Узел должен быть остановлен.

  pp vault-restore -in FILE [-data DIR] [-key PATH] [-force]
      распаковка архива в data, открытие vault мастер-ключом и проверка журнала.
      Отказывается перезаписывать существующий vault.db без -force.
      Восстановление на «чистую» машину требует -key (или переноса data/pp.local).

  pp version
`, version)
}

func parse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	data := fs.String("data", exeDataDir(), "data directory (default: <dir-of-this-binary>/data)")
	key := fs.String("key", "", "full master key file (rescue/dev single-key mode; default: two halves — local + USB stick)")
	rescueOut := fs.String("rescue-out", "", "write the combined full master key to FILE for safe-keeping")
	node := fs.String("node", "", "short node name written into both halves and suggested for the stick label (default auto node-<hex>)")
	adminOut := fs.String("admin-out", "", "file to write the admin private key (default <data>/admin.pem)")
	ips := fs.String("ips", "", "comma-separated LAN IPs to embed into the TLS certificate (for https/wss access)")
	noTLS := fs.Bool("no-tls", false, "skip generating the self-signed TLS certificate")
	parse(fs, args)

	if *adminOut == "" {
		*adminOut = filepath.Join(*data, "admin.pem")
	}
	vaultPath := filepath.Join(*data, "vault.db")
	if _, err := os.Stat(vaultPath); err == nil {
		log.Fatalf("init: %s already exists — узел уже развёрнут (удалите %s, чтобы переустановить)", vaultPath, *data)
	}

	var mk *crypto.MasterKey
	if *key != "" {
		var err error
		mk, err = loadOrCreateMaster(*key)
		if err != nil {
			log.Fatalf("init: master key: %v", err)
		}
	} else {
		src, err := resolveKeySource(*key, *data, false, true, *node)
		if err != nil {
			log.Fatalf("init: %v", err)
		}
		mk, err = crypto.CreateHalvesWithID(src.localHalf, src.usbHalf, src.nodeID, src.nodeName)
		if err != nil {
			log.Fatalf("init: master key halves: %v", err)
		}
		fmt.Printf("master key halves: local=%s usb=%s (узел %q)\n", src.localHalf, src.usbHalf, src.nodeName)
	}
	defer mk.Destroy()

	if *rescueOut != "" {
		if err := os.WriteFile(*rescueOut, mk.Bytes(), 0o600); err != nil {
			log.Fatalf("init: rescue-out write: %v", err)
		}
		fmt.Printf("rescue master key written to %s (храните в сейфе, отдельно от флешки)\n", *rescueOut)
	}

	initNode(*data, *adminOut, mk, splitCSV(*ips), *noTLS)
}

// initNode performs first-time deployment: the (already resolved) master key,
// encrypted vault, admin operator key, internal CA and the node TLS
// certificate. It is invoked by `pp init` and, in wizard mode, by `pp run`
// when no vault exists yet.
func initNode(data, adminOut string, mk *crypto.MasterKey, ips []string, noTLS bool) {
	st, err := db.Open(data, mk.Bytes())
	if err != nil {
		log.Fatalf("init: db: %v", err)
	}

	err = st.Persist(context.Background())
	if err != nil {
		log.Fatalf("init: persist: %v", err)
	}

	ctx := context.Background()
	if _, err := st.SubscriberByCallsign(ctx, "admin"); err == db.ErrNotFound {
		res, err := ca.Create(ctx, st, "admin", "admin")
		if err != nil {
			log.Fatalf("init: admin: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(adminOut), 0o700); err != nil {
			log.Fatalf("init: admin-out dir: %v", err)
		}
		if err := os.WriteFile(adminOut, []byte(res.PrivatePEM), 0o600); err != nil {
			log.Fatalf("init: admin-out write: %v", err)
		}
		fmt.Printf("admin key written to %s\n", adminOut)
	} else {
		fmt.Println("admin key already exists, skipped")
	}

	if err := st.Close(ctx); err != nil {
		log.Fatalf("init: close: %v", err)
	}
	fmt.Printf("initialized: data=%q vault=%q master_key=halves(local+USB)\n", data, filepath.Join(data, "vault.db"))

	if noTLS {
		fmt.Println("tls: skipped (use 'pp run -tls' needs data/tls.crt + data/tls.key)")
		return
	}
	certPath := filepath.Join(data, "tls.crt")
	keyPath := filepath.Join(data, "tls.key")
	caCertPath := filepath.Join(data, "ca.crt")
	caKeyPath := filepath.Join(data, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		fmt.Println("tls: certificate already exists, skipped")
		return
	}
	if _, err := os.Stat(caCertPath); err != nil {
		if err := crypto.WriteCACert(caCertPath, caKeyPath, "PrivatePhone Mesh CA"); err != nil {
			log.Fatalf("init: ca: %v", err)
		}
		fmt.Printf("tls: mesh CA written (%s, %s)\n", caCertPath, caKeyPath)
	}
	if err := crypto.WriteServerTLSCert(caCertPath, caKeyPath, certPath, keyPath, ips, "ПАК АСК offline node"); err != nil {
		log.Fatalf("init: tls: %v", err)
	}
	fmt.Printf("tls: node certificate written (%s, %s)\n", certPath, keyPath)
	fmt.Println("tls: enable with 'pp run -tls'; import data/ca.crt as a trusted root on subscriber devices — one root covers the whole mesh (https/wss + WebRTC secure context)")
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadOrCreateMaster(path string) (*crypto.MasterKey, error) {
	if _, err := os.Stat(path); err == nil {
		return crypto.LoadMasterKey(path)
	}
	mk, err := crypto.CreateMasterKey(path)
	if err != nil {
		return nil, err
	}
	fmt.Printf("master key created on %s (keep the USB flash safe)\n", path)
	return mk, nil
}

// loadKeyFor opens the vault master key for maintenance subcommands: a full
// single key file when -key is given (rescue/dev mode), otherwise the two
// halves — the local half in the data dir plus a confirmed USB half.
func loadKeyFor(data, keyFlag string) *crypto.MasterKey {
	if keyFlag != "" {
		mk, err := crypto.LoadMasterKey(keyFlag)
		if err != nil {
			log.Fatalf("master key: %v", err)
		}
		return mk
	}
	src, err := resolveKeySource(keyFlag, data, true, false, "")
	if err != nil {
		log.Fatalf("master key: %v", err)
	}
	mk, err := crypto.KeyFromHalves(src.localHalf, src.usbHalf)
	if err != nil {
		log.Fatalf("master key halves: %v", err)
	}
	return mk
}

func cmdVerifyJournal(args []string) {
	fs := flag.NewFlagSet("verify-journal", flag.ExitOnError)
	key := fs.String("key", "", "full master key file (rescue mode); default: two halves — <data>/pp.local + USB stick")
	data := fs.String("data", "./data", "data directory")
	parse(fs, args)
	mk := loadKeyFor(*data, *key)
	ctx := context.Background()
	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("verify-journal: db: %v", err)
	}
	bad, head, err := st.VerifyJournal(ctx)
	count := 0
	if rows, rerr := st.ListJournal(ctx, 0); rerr == nil {
		count = len(rows)
	}
	_ = st.Close(ctx)
	mk.Destroy()
	if err != nil {
		log.Fatalf("verify-journal: %v", err)
	}
	if bad >= 0 {
		fmt.Fprintf(os.Stderr, "verify-journal: TAMPERED at journal index %d (chain broken)\n", bad)
		os.Exit(1)
	}
	fmt.Printf("verify-journal: OK — %d rows intact, head=%s\n", count, head)
}

func cmdJournalExport(args []string) {
	fs := flag.NewFlagSet("journal-export", flag.ExitOnError)
	key := fs.String("key", "", "full master key file (rescue mode); default: two halves — <data>/pp.local + USB stick")
	data := fs.String("data", "./data", "data directory")
	after := fs.Int64("after", 0, "export only packets with ts >= AFTER")
	out := fs.String("out", "-", "output file ('-' = stdout)")
	parse(fs, args)
	mk := loadKeyFor(*data, *key)
	ctx := context.Background()
	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("journal-export: db: %v", err)
	}
	entries, err := st.ListJournal(ctx, *after)
	if err != nil {
		_ = st.Close(ctx)
		mk.Destroy()
		log.Fatalf("journal-export: journal: %v", err)
	}
	if entries == nil {
		entries = []db.JournalEntry{}
	}
	head, err := st.JournalHead(ctx)
	if err != nil {
		_ = st.Close(ctx)
		mk.Destroy()
		log.Fatalf("journal-export: head: %v", err)
	}
	_ = st.Close(ctx)
	mk.Destroy()

	bag, err := json.MarshalIndent(map[string]any{"head": head, "entries": entries}, "", "  ")
	if err != nil {
		log.Fatalf("journal-export: marshal: %v", err)
	}
	if *out == "-" {
		fmt.Println(string(bag))
		return
	}
	if err := os.WriteFile(*out, bag, 0o600); err != nil {
		log.Fatalf("journal-export: write %s: %v", *out, err)
	}
	fmt.Printf("journal-export: %d entries (ts >= %d), head=%s -> %s\n", len(entries), *after, head, *out)
}

func cmdJournalImport(args []string) {
	fs := flag.NewFlagSet("journal-import", flag.ExitOnError)
	key := fs.String("key", "", "full master key file (rescue mode); default: two halves — <data>/pp.local + USB stick")
	data := fs.String("data", "./data", "data directory")
	in := fs.String("in", "", "bag file ('-' = stdin, required)")
	parse(fs, args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "journal-import: -in bag file is required")
		os.Exit(2)
	}
	var raw []byte
	var err error
	if *in == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*in)
	}
	if err != nil {
		log.Fatalf("journal-import: read %s: %v", *in, err)
	}

	var bag struct {
		Head    string            `json:"head"`
		Entries []db.JournalEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &bag); err != nil {
		if arrErr := json.Unmarshal(raw, &bag.Entries); arrErr != nil {
			log.Fatalf("journal-import: bag format: %v", err)
		}
	}

	mk := loadKeyFor(*data, *key)
	ctx := context.Background()
	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("journal-import: db: %v", err)
	}
	ver := &protocol.Verifier{Subs: func(ctx context.Context, callsign string) (string, string, error) {
		sub, err := st.SubscriberByCallsign(ctx, callsign)
		if err != nil {
			return "", "", err
		}
		return sub.PubKey, sub.Role, nil
	}}
	hub := ws.NewHub(st, ver)
	rep, err := hub.ImportBag(ctx, bag.Entries)
	_ = st.Close(ctx)
	mk.Destroy()
	if err != nil {
		log.Fatalf("journal-import: %v", err)
	}
	if rep.Rejected {
		fmt.Fprintf(os.Stderr, "journal-import: REJECTED at index %d: %s (nothing imported)\n", rep.RejectedAt, rep.RejectedWhy)
		os.Exit(1)
	}
	fmt.Printf("journal-import: added_journal=%d skipped_duplicates=%d skipped_context=%d head=%s, now verified locally\n",
		rep.AddedJournal, rep.SkippedDup, rep.SkippedCtx, rep.Head)
}

func cmdVaultBackup(args []string) {
	fs := flag.NewFlagSet("vault-backup", flag.ExitOnError)
	key := fs.String("key", "", "full master key file (rescue mode); default: two halves — <data>/pp.local + USB stick")
	data := fs.String("data", "./data", "data directory")
	out := fs.String("out", "", "backup archive path (required)")
	parse(fs, args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "vault-backup: -out archive path is required")
		os.Exit(2)
	}

	mk := loadKeyFor(*data, *key)
	// Opening with the master key proves the vault decrypts and flushes a
	// consistent sealed snapshot before the archive is built.
	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("vault-backup: db: %v", err)
	}
	if err := st.Close(context.Background()); err != nil {
		mk.Destroy()
		log.Fatalf("vault-backup: persist: %v", err)
	}
	mk.Destroy()

	names := []string{"vault.db", "tls.crt", "tls.key", "ca.crt", "ca.key", "admin.pem"}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		log.Fatalf("vault-backup: out dir: %v", err)
	}
	outf, err := os.Create(*out)
	if err != nil {
		log.Fatalf("vault-backup: create %s: %v", *out, err)
	}
	gz := gzip.NewWriter(outf)
	tw := tar.NewWriter(gz)
	manifest := map[string]any{"format": "privatephone-vault-backup-v1", "created_at": time.Now().UTC().Format(time.RFC3339)}
	files := map[string]string{}
	for _, name := range names {
		path := filepath.Join(*data, name)
		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Fatalf("vault-backup: stat %s: %v", path, err)
		}
		sum, err := sha256File(path)
		if err != nil {
			log.Fatalf("vault-backup: hash %s: %v", path, err)
		}
		files[name] = sum
		if err := writeTarFile(tw, name, path, fi); err != nil {
			log.Fatalf("vault-backup: tar %s: %v", path, err)
		}
	}
	manifest["files"] = files
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	hdr := &tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(mb)), ModTime: time.Now()}
	if err := tw.WriteHeader(hdr); err == nil {
		_, _ = tw.Write(mb)
	}
	if err := tw.Close(); err != nil {
		log.Fatalf("vault-backup: tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		log.Fatalf("vault-backup: gzip close: %v", err)
	}
	if err := outf.Close(); err != nil {
		log.Fatalf("vault-backup: close: %v", err)
	}
	joined := make([]string, 0, len(files))
	for k := range files {
		joined = append(joined, k)
	}
	fmt.Printf("vault-backup: %d files (%s) -> %s\n", len(files), strings.Join(joined, ", "), *out)
}

func cmdVaultRestore(args []string) {
	fs := flag.NewFlagSet("vault-restore", flag.ExitOnError)
	in := fs.String("in", "", "backup archive path (required)")
	key := fs.String("key", "", "full master key file (rescue mode); default: two halves — <data>/pp.local + USB stick")
	data := fs.String("data", "./data", "data directory")
	force := fs.Bool("force", false, "overwrite an existing vault.db")
	parse(fs, args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "vault-restore: -in is required")
		os.Exit(2)
	}
	vaultPath := filepath.Join(*data, "vault.db")
	if _, err := os.Stat(vaultPath); err == nil && !*force {
		log.Fatalf("vault-restore: %s already exists; use -force to replace it (back it up first)", vaultPath)
	}
	mk := loadKeyFor(*data, *key)
	if err := os.MkdirAll(*data, 0o700); err != nil {
		mk.Destroy()
		log.Fatalf("vault-restore: data dir: %v", err)
	}
	inf, err := os.Open(*in)
	if err != nil {
		log.Fatalf("vault-restore: open %s: %v", *in, err)
	}
	defer inf.Close()
	gz, err := gzip.NewReader(inf)
	if err != nil {
		log.Fatalf("vault-restore: gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	restored := []string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("vault-restore: archive read: %v", err)
		}
		name := filepath.Base(filepath.Clean(hdr.Name))
		if name == "." || name == "manifest.json" || len(name) > 32 {
			continue
		}
		path := filepath.Join(*data, name)
		out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("vault-restore: create %s: %v", path, err)
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			log.Fatalf("vault-restore: write %s: %v", path, err)
		}
		restored = append(restored, name)
	}

	ctx := context.Background()
	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("vault-restore: vault does not open with this master key: %v", err)
	}
	bad, head, err := st.VerifyJournal(ctx)
	count := 0
	if rows, rerr := st.ListJournal(ctx, 0); rerr == nil {
		count = len(rows)
	}
	_ = st.Close(ctx)
	mk.Destroy()
	if err != nil {
		log.Fatalf("vault-restore: verify: %v", err)
	}
	if bad >= 0 {
		log.Fatalf("vault-restore: journal TAMPERED at index %d", bad)
	}
	fmt.Printf("vault-restore: %s -> %s, journal intact: %d rows, head=%s\n", *in, *data, count, head)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeTarFile(tw *tar.Writer, name, path string, fi os.FileInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	port := fs.String("port", ":8080", "listen address")
	data := fs.String("data", exeDataDir(), "data directory (default: <dir-of-this-binary>/data)")
	key := fs.String("key", "", "full master key file (rescue/dev single-key mode; default: two halves — <data>/pp.local + USB stick)")
	node := fs.String("node", "", "node name for first-run wizard (default auto node-<hex>)")
	watch := fs.Bool("watch", true, "kill the process when the USB flash (key carrier) is removed")
	persistEvery := fs.Duration("persist", 5*time.Second, "vault persist interval")
	skew := fs.Duration("clock-skew", crypto.DefaultSkewWindow, "freshness window for packet timestamps")
	calibrate := fs.Bool("clock-calibrate", false, "track the clock offset from admin packets")
	tls := fs.Bool("tls", false, "serve HTTPS/WSS using <data>/tls.crt and <data>/tls.key")
	parse(fs, args)

	tlsSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "tls" {
			tlsSet = true
		}
	})

	adminOut := filepath.Join(*data, "admin.pem")
	vaultPath := filepath.Join(*data, "vault.db")
	_, vaultErr := os.Stat(vaultPath)
	vaultExists := vaultErr == nil
	firstRun := !vaultExists

	noKeyFlag := *key == ""
	if noKeyFlag && !tlsSet {
		// Авторежим — по умолчанию HTTPS (WebRTC нужно secure context) и
		// инструкции первого запуска должны показать верный адрес https://.
		*tls = true
		log.Printf("http: -tls enabled automatically; укажите -tls=false для HTTP")
	}

	// Ключ: либо явный полный файл (-key, резервный режим), либо две половины
	// — локальная <data>/pp.local и USB-половина pp.key с флешки, которую
	// сервер находит сам и просит подтвердить.
	var mk *crypto.MasterKey
	if noKeyFlag {
		src, err := resolveKeySource(*key, *data, vaultExists, firstRun, *node)
		if err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			os.Exit(2)
		}
		if firstRun {
			mk, err = crypto.CreateHalvesWithID(src.localHalf, src.usbHalf, src.nodeID, src.nodeName)
			if err != nil {
				log.Fatalf("run: master key halves: %v", err)
			}
			fmt.Printf("run: создан мастер-ключ: локальная половина %s + USB-половина %s (узел %q)\n",
				src.localHalf, src.usbHalf, src.nodeName)
			*node = src.nodeName
		} else {
			mk, err = crypto.KeyFromHalves(src.localHalf, src.usbHalf)
			if err != nil {
				log.Fatalf("run: master key halves: %v", err)
			}
			fmt.Printf("run: мастер-ключ из половин: %s + %s\n", src.localHalf, src.usbHalf)
		}
	} else if firstRun {
		var err error
		mk, err = loadOrCreateMaster(*key)
		if err != nil {
			log.Fatalf("run: master key: %v", err)
		}
	} else {
		var err error
		mk, err = crypto.LoadMasterKey(*key)
		if err != nil {
			log.Fatalf("run: master key: %v", err)
		}
	}

	if firstRun {
		// Мастер первого запуска: vault, админ, CA + TLS, SAN с
		// автоопределённым LAN-IP — без единого флага.
		ips := []string{}
		if ip := firstLANIPv4(); ip != "" {
			ips = append(ips, ip)
		}
		initNode(*data, adminOut, mk, ips, false)
		scheme := "http"
		if *tls {
			scheme = "https"
		}
		printFirstRun(*data, *port, scheme, adminOut, *node, ips)
	}

	defer mk.Destroy()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := db.Open(*data, mk.Bytes())
	if err != nil {
		mk.Destroy()
		log.Fatalf("run: db: %v", err)
	}
	st.PersistentEvery(ctx, *persistEvery)
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := st.Close(shCtx); err != nil {
			log.Printf("final persist failed: %v", err)
		}
		mk.Destroy()
	}()

	ver := &protocol.Verifier{
		Guard: crypto.NewReplayGuard(10000, *skew),
		Subs: func(ctx context.Context, callsign string) (string, string, error) {
			sub, err := st.SubscriberByCallsign(ctx, callsign)
			if err != nil {
				return "", "", err
			}
			if sub.Revoked != 0 {
				return "", "", protocol.ErrRevoked
			}
			return sub.PubKey, sub.Role, nil
		},
	}
	if *calibrate {
		ver.Skew = crypto.NewClockOffset()
		log.Printf("clock calibration enabled: learning offset from admin packets (max ±%s)", crypto.MaxClockCorrection)
	}

	hub := ws.NewHub(st, ver)
	srv := api.New(st, hub, ver, config.NormalizeAddr(*port))
	if *tls {
		cert := filepath.Join(*data, "tls.crt")
		key := filepath.Join(*data, "tls.key")
		if _, err := os.Stat(cert); err != nil {
			log.Fatalf("run: -tls requested but %s missing (run 'pp init -ips <LAN_IP>' first)", cert)
		}
		srv.WithTLS(cert, key)
	}

	if *watch {
		mk.Watch(time.Second, func() {
			log.Println("USB KEY CARRIER REMOVED — zeroing key and terminating")
			shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = st.Close(shCtx)
			os.Exit(1)
		})
	}

	if err := srv.Serve(ctx); err != nil {
		log.Printf("server stopped: %v", err)
	}
}
