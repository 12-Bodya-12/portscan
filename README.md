# portscan

Go-пакет для конкурентного TCP Connect-сканирования портов на одном или нескольких хостах.
Не использует сторонних зависимостей, не хранит глобального изменяемого состояния и готов к встраиванию в любые Go-приложения.

## Требования

- Go 1.25.5+

## Быстрый старт

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/12-Bodya-12/portscan"
)

func main() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"192.168.1.10", "example.com", "::1"},
		portscan.Ports(22, 80, 443),
		portscan.Range(8000, 8010),
	)
	if err != nil {
		log.Fatal(err)
	}

	for res := range results {
		fmt.Printf("%s (%s):%d -> %s (%s)\n",
			res.Host, res.IP, res.Port, res.State, res.Duration)
	}
}
```

## Публичный API

### Создание сканера

```go
func New(opts ...Option) (*Scanner, error)
```

Доступные опции:

| Опция | По умолчанию | Описание |
|---|---|---|
| `WithConcurrency(n int)` | `100` | Максимальное число одновременных подключений на один вызов `Scan` |
| `WithConnectTimeout(d time.Duration)` | `1s` | Таймаут одного TCP-подключения |
| `WithResolveTimeout(d time.Duration)` | `5s` | Таймаут DNS-разрешения одного хоста |
| `WithResolvePolicy(p ResolvePolicy)` | `ResolveAll` | `ResolveAll` (все уникальные IP) или `ResolveFirst` (первый IP) |
| `WithResultBuffer(n int)` | `min(concurrency, 1024)` | Размер буфера канала результатов |
| `WithDialer(d Dialer)` | `&net.Dialer{}` | Пользовательский dialer (`DialContext`) |
| `WithResolver(r Resolver)` | `net.DefaultResolver` | Пользовательский DNS-резолвер (`LookupNetIP`) |

`Scanner` неизменяем после создания: один экземпляр можно безопасно использовать повторно и вызывать `Scan` конкурентно из разных горутин.

### Запуск сканирования и спецификации портов

```go
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports ...PortSpec) (<-chan Result, error)
```

Конструкторы портов:

- `Ports(ports ...int) PortSpec` — список отдельных портов;
- `Range(from, to int) PortSpec` — включительный диапазон `[from, to]`;
- `Combine(specs ...PortSpec) PortSpec` — объединение нескольких спецификаций.

Дополнительный хелпер для CIDR:

- `ExpandCIDR(cidr string) ([]string, error)` — разворачивает IPv4/IPv6 CIDR (до `/16` хостов). Для IPv4-сетей `<= /30` исключаются адрес сети и broadcast.

### Структура результата и состояния

```go
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
```

Состояния (`State`):

- `StateOpen` (`"open"`) — TCP-соединение установлено и корректно закрыто;
- `StateClosed` (`"closed"`) — соединение явно отклонено (`ECONNREFUSED` / `WSAECONNREFUSED`);
- `StateTimeout` (`"timeout"`) — истёк таймаут подключения (`connectTimeout`) или сетевой таймаут;
- `StateUnreachable` (`"unreachable"`) — узел или сеть недоступны (`EHOSTUNREACH`, `ENETUNREACH`, `EHOSTDOWN`, `ENETDOWN`);
- `StateCanceled` (`"canceled"`) — проверка прервана через переданный `ctx`;
- `StateError` (`"error"`) — прочая сетевая ошибка или ошибка DNS-резолвинга.

Классификация состояний выполняется исключительно через `errors.Is` / `errors.As` без сравнения текста ошибок.

## Поведение в граничных случаях

### Цели сканирования
- **Пустой список хостов:** `Scan` возвращает `ErrEmptyHosts`.
- **Пустой хост (`""`, пробелы):** `Scan` возвращает `ErrEmptyHost`.
- **Некорректный адрес (пробелы, `host:port`, `999.999.999.999`, невалидный DNS):** `Scan` возвращает `ErrInvalidHost`.
- **Повторяющиеся цели:** автоматически дедуплицируются с сохранением порядка (IP канонизируются через `netip.Addr.Unmap`, DNS нормализуются без учёта регистра и завершающей точки).
- **Неразрешимое DNS-имя:** не прерывает сканирование остальных целей; в канал отправляется один `Result` с `Port: 0`, `State` (`error` / `timeout` / `canceled`) и `Err`, оборачивающей `ErrResolveFailed`.
- **Несколько IP на одно DNS-имя:** при `ResolveAll` сканируются все уникальные IP, при `ResolveFirst` — только первый.

### Порты
- **Порт `0`, `< 0` или `> 65535`:** `Scan` возвращает `ErrInvalidPort`.
- **Обратный диапазон (например `Range(1000, 1)`):** `Scan` возвращает `ErrInvalidPortRange`.
- **Пустой итоговый набор портов:** `Scan` возвращает `ErrEmptyPorts`.
- **Повторяющиеся и пересекающиеся порты:** автоматически дедуплицируются и сканируются один раз в порядке возрастания.

### Конкурентность и отмена
- Задания генерируются потоково без предварительного выделения памяти под все пары `(host, port)`.
- Медленное чтение из канала результатов создаёт backpressure и тормозит генерацию новых задач.
- При отмене `ctx` новые задания перестают отправляться, активные `DialContext` прерываются, все горутины корректно завершаются (даже если вызывающий код перестал читать канал), а выходной канал закрывается.
- Если в `Scan` передан уже отменённый `ctx`, немедленно возвращается закрытый пустой канал без запуска горутин.

## Тестирование

```bash
go test -race -v ./...
```
