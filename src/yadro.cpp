#include <variant>
#include <span>
#include <string_view>
#include <algorithm>
#include <array>

#include <gtest/gtest.h>

using namespace std::literals::string_view_literals;

// вспомогательный тип для сбоки лямбд в один функциональный объект
template<typename... Ts>
struct Overloads : Ts... {
	using Ts::operator()...;
};

// "оператор" match для std::variant
template<typename... Ts>
using match = Overloads<Ts...>;

enum class Error {
	resource_not_found = -1,
};

namespace detail {

	template<typename T, typename E>
	struct [[nodiscard]] ResultWrapper : public std::variant<T, E> {
		using std::variant<T, E>::variant;
		using std::variant<T, E>::index;

		bool isOk() const noexcept {
			return index() == 0;
		}

		bool isErr() const noexcept {
			return index() == 1;
		}

		T unwrapOr(T && val) noexcept {
			if (isOk())
				return std::get<0>(std::move(*this));
			else
				return std::forward<T>(val);
		}

		T unwrap() {
			if (isOk())
				return std::get<0>(std::move(*this));
			else
				throw std::runtime_error("panic!");
		}
	};

}

template<typename T>
using Result = detail::ResultWrapper<T, Error>;

template<typename Mode>
struct access_mode_trait;

template<>
struct access_mode_trait<bool> {
	enum {
		allow = true,
		deny = false,
	};
};

template<typename RESOURCE, typename CLIENT, typename ACCESS_MODE = bool>
class ACL final {
	struct Relation
	{
		uint32_t resource;
		uint32_t client;
		ACCESS_MODE mode;
	};

	static inline const auto by_resource_id = Overloads{
			[](Relation r, uint32_t id) -> bool {
				return r.resource < id;
			},
			[](uint32_t id, Relation r) -> bool {
				return id < r.resource;
			},
			[](Relation lhs, Relation rhs) -> bool {
				return lhs.resource < rhs.resource;
			},
		};

	static inline const auto by_client_id = Overloads{
			[](Relation r, uint32_t id) -> bool {
				return r.client < id;
			},
			[](Relation lhs, Relation rhs) -> bool {
				return lhs.client < rhs.client;
			},
		};

public:
	auto add(RESOURCE& res, CLIENT& client, ACCESS_MODE mode) -> void {
		// Могут ли быть дубликаты в отношениях ресурс/клиент?

		r_to_c.emplace_back(res.id, client.id, mode);

		// Открытый вопрос: когда лучше сортировать записи? При добавлении или при первом чтении.
		std::stable_sort(r_to_c.begin(),r_to_c.end(),by_client_id);
		std::stable_sort(r_to_c.begin(),r_to_c.end(),by_resource_id);
	}

	auto get(RESOURCE& res, CLIENT& client) const -> Result<ACCESS_MODE> {
		// Если запрашиваемой комбинации ресурс/клиент нет в списке?
		// Возвращать запрет на доступ или ошибку?

		const auto [lo, hi] = std::equal_range(r_to_c.cbegin(), r_to_c.cend(), res.id, by_resource_id);

		if(lo == hi)
			return Error::resource_not_found;

		auto it = std::lower_bound(lo, hi,client.id, by_client_id);

		if(it == hi || it->client != client.id)
			return Error::resource_not_found;

		return it->mode;
	}

	// Расширение интерфейса
public:
	// Удаление ресурса
	auto remove(RESOURCE& res) -> void {
		const auto [lo, hi] = std::equal_range(r_to_c.cbegin(), r_to_c.cend(), res.id, by_resource_id);

		// Не нарушает порядок сортировки
		r_to_c.erase(lo, hi);
	}

	// Удаление у всех ресурсов записей о клиенте
	auto remove(CLIENT& client) -> void {
		// Да, да... линейный поиск. Я знаю.
		// Не нарушает порядок сортировки
		const auto it = std::remove_if(r_to_c.begin(), r_to_c.end(), [&](const Relation& r) -> bool {
			return r.client == client.id;
			});

		r_to_c.erase(it, r_to_c.end());
	}

	// Разрешить группе клиентов доступ к ресурсу
	auto allow(RESOURCE& res, std::span<CLIENT> clients) -> void {
		apply(res, clients, access_mode_trait<ACCESS_MODE>::allow);
	}

	// Запретить группе клиентов доступ к ресурсу
	auto deny(RESOURCE& res, std::span<CLIENT> clients) -> void {
		apply(res, clients, access_mode_trait<ACCESS_MODE>::deny);
	}

	// Разрешить всем доступ к ресурсу
	auto allow(RESOURCE& res) -> void {
		apply(res, access_mode_trait<ACCESS_MODE>::allow);
	}

	// Запретить всем доступ к ресурсу
	auto deny(RESOURCE& res) -> void {
		apply(res, access_mode_trait<ACCESS_MODE>::deny);
	}

private:
	// Применить права доступа к ресурсу.
	// 
	// Метод может быть потенциально уязвим.
	// Достаточно в код, вычисляющий режим доступа вкрасться ошибке и
	// вот уже функция, которая раньше запрещала доступ к ресурсу
	// разрешает всем доступ.
	// Поэтому положим его в закрытую секцию,а в публичной секциии
	// сделаем две обертки, выполняющих конкретные действия.
	auto apply(RESOURCE& res, ACCESS_MODE mode) -> void {
		const auto [lo, hi] = std::equal_range(r_to_c.begin(), r_to_c.end(), res.id, by_resource_id);

		if (lo == hi)
			return;

		std::for_each(lo, hi, [=](Relation& r)  -> void {
			r.mode = mode;
			});
	}

	// Применить права доступа для группы клиентов.
	// 
	// Вообще не очень хорошая практика передавать "флаги" в функцию.
	// Особенно в случаях, напрямую влияющих на безопасность системы.
	// Потому что в точке вызова по сигнатуре непонятно какой режим
	// доступа предоставляется на самом деле.
	// Лучше будет разделить на запрещающие и разрешающие права,
	// чтобы ситуации когда права нужно запретить в коде выглядели явно.
	auto apply(RESOURCE& res, std::span<CLIENT> clients, ACCESS_MODE mode) -> void {
		const auto [lo, hi] = std::equal_range(r_to_c.begin(), r_to_c.end(), res.id, by_resource_id);

		if (lo == hi)
			return;

		for (auto& client : clients) {
			const auto it = std::lower_bound(lo, hi, client.id, by_client_id);

			if (it == hi || it->client != client.id)
				continue;

			it->mode = mode;
		}
	}

	// Один пользователь может иметь доступ к нескольким ресурсам.
	// К одному ресурсу могут иметь доступ несколько пользователей.
	// Это классическое отношение "многие ко многим".
	// Предполагаем, что читать записи будут намного чаще, чем писать.
	// Здесь, по идее, нужна структура по типу таблиц в БД, чтобы можно было
	// индексировать записи по ресусу и по клиенту и быстро добавлять/удалять записи.
	// Пусть в первом прближении будет сортированный вектор. Можно хотя бы
	// сравнительно быстро искать/удалять записи.
	std::vector<Relation> r_to_c;
};

namespace client::id {
	uint32_t create() {
		static uint32_t start_from = 0;

		return start_from++;
	}
}

namespace resource::id {
	uint32_t create() {
		static uint32_t start_from = 1 << 16;

		return start_from++;
	}
}

struct Client {
	uint32_t id;
	std::string_view nick;

	static Client create(std::string_view nick) {
		return {
			.id = client::id::create(),
			.nick = nick,
		};
	}
};

struct Resource {
	uint32_t id;
	std::string_view location;

	static Resource create(std::string_view location) {
		return {
			.id = resource::id::create(),
			.location = location,
		};
	}
};

enum class UnixMode {
	deny  = 0b000,
	view  = 0b001,
	read  = 0b011,
	write = 0b111,
};

template<>
struct access_mode_trait<UnixMode> {
	enum {
		allow = UnixMode::write,
		deny  = UnixMode::deny,
	};
};

TEST(ResultUnit, is_ok_is_err) {
	auto ok = Result<bool>(true);

	EXPECT_TRUE(ok.isOk());
	EXPECT_FALSE(ok.isErr());

	auto err = Result<bool>(Error::resource_not_found);
	EXPECT_TRUE(err.isErr());
	EXPECT_FALSE(err.isOk());
}

TEST(ClientUnit, id_monotonic_grows) {
	uint32_t id = client::id::create();

	EXPECT_TRUE(id < (1 << 16));
	EXPECT_EQ(++id, client::id::create());
	EXPECT_EQ(++id, client::id::create());
	EXPECT_EQ(++id, client::id::create());
}

TEST(ClientUnit, check_creating) {
	auto client = Client::create("client");

	EXPECT_TRUE(client.id < (1 << 16));
	EXPECT_EQ("client"sv, client.nick);
}

TEST(ResourceUnit, id_monotonic_grows) {
	uint32_t id = resource::id::create();

	EXPECT_TRUE(id >= (1 << 16));
	EXPECT_EQ(++id, resource::id::create());
	EXPECT_EQ(++id, resource::id::create());
	EXPECT_EQ(++id, resource::id::create());
}

TEST(ResourceUnit, check_creating) {
	auto file = Resource::create("file");

	EXPECT_TRUE(file.id >= (1 << 16));
	EXPECT_EQ("file"sv, file.location);
}

class ACLUnit : public testing::Test {
protected:
	ACLUnit()
		: root{ Client::create("root") }
		, admin{ Client::create("admin") }
		, user{ Client::create("user") }
		, guest{ Client::create("guest") }
		, folder{ Resource::create("folder") }
		, file{ Resource::create("file") }
		, socket{ Resource::create("socket") }
		, process{ Resource::create("process") }
	{
	}

	~ACLUnit() override = default;

	Client root;
	Client admin;
	Client user;
	Client guest;

	Resource folder;
	Resource file;
	Resource socket;
	Resource process;
};

class ACLWithDefaultAccess : public ACLUnit {
protected:
	ACL<Resource, Client> acl;

	void SetUp() override {
		// root пользователь имеет доступ ко всем ресурсам.
		acl.add(folder, root, true);
		acl.add(file, root, true);
		acl.add(socket, root, true);
		acl.add(process, root, true);

		// guest пользователь не имеет доступа ни к чему
		acl.add(folder, guest, false);
		acl.add(file, guest, false);
		acl.add(socket, guest, false);
		acl.add(process, guest, false);

		// пользователи admin и user имеют смешанный доступ
		acl.add(folder, admin, false);
		acl.add(file, admin, true);
		acl.add(socket, admin, true);
		acl.add(process, admin, false);

		acl.add(folder, user, true);
		acl.add(file, user, false);
		acl.add(socket, user, false);
		acl.add(process, user, true);
	}

	void TearDown() override {
	}
};

TEST_F(ACLWithDefaultAccess, adding_and_getting) {
	// проверяем пользователя root
	auto mode = acl.get(folder, root);
	std::visit(match{
			[](bool ok) { EXPECT_TRUE(ok); },
			[](Error err) { EXPECT_TRUE(false) << "Method ACL::get must return Ok but we got Err"; },
		},
		mode);

	mode = acl.get(file, root);
	std::visit(match{
			[](bool ok) { EXPECT_TRUE(ok); },
			[](Error err) { EXPECT_TRUE(false) << "Method ACL::get must return Ok but we got Err"; },
		},
		mode);

	mode = acl.get(socket, root);
	std::visit(match{
			[](bool ok) { EXPECT_TRUE(ok); },
			[](Error err) { EXPECT_TRUE(false) << "Method ACL::get must return Ok but we got Err"; },
		},
		mode);

	mode = acl.get(process, root);
	std::visit(match{
			[](bool ok) { EXPECT_TRUE(ok); },
			[](Error err) { EXPECT_TRUE(false) << "Method ACL::get must return Ok but we got Err"; },
		},
		mode);

	// проверяем пользователя guest
	mode = acl.get(folder, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());
	
	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(socket, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(process, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	// проверяем пользователя admin
	mode = acl.get(folder, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());
	
	mode = acl.get(socket, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(process, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	// проверяем пользователя user
	mode = acl.get(folder, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(socket, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(process, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());
}

TEST_F(ACLWithDefaultAccess, allow_resource) {
	// разрешаем всем доступ к ресурсу
	acl.allow(file);

	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());
}

TEST_F(ACLWithDefaultAccess, deny_resource) {
	// запрещаем всем доступ к ресурсу
	acl.deny(file);

	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());
}

TEST_F(ACLWithDefaultAccess, allow_resource_by_user_group) {
	// запрещаем всем доступ к ресурсу
	acl.deny(file);

	// разрешаем только трем пользователям
	std::array<Client, 3> clients = { {root, admin, user} };

	acl.allow(file, std::span<Client>(clients));

	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());
}

TEST_F(ACLWithDefaultAccess, deny_resource_by_user_group) {
	// разрешаем всем доступ к ресурсу
	acl.allow(file);

	// запрещаем только трем пользователям
	std::array<Client, 3> clients = { {root, admin, user} };

	acl.deny(file, std::span<Client>(clients));

	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_FALSE(mode.unwrap());

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_TRUE(mode.unwrap());
}

TEST_F(ACLWithDefaultAccess, remove_resource) {
	// удаляем ресурс
	acl.remove(file);

	// файл не найден
	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	// остальные ресурсы доступны
	mode = acl.get(folder, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";

	mode = acl.get(socket, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";

	mode = acl.get(process, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
}

TEST_F(ACLWithDefaultAccess, remove_client) {
	// удаляем клиента
	acl.remove(root);

	// пользователя root больше нет в списке
	auto mode = acl.get(file, root);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(folder, root);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(socket, root);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	mode = acl.get(process, root);
	ASSERT_TRUE(mode.isErr()) << "Method ACL::get must return Err but we got Ok";

	// остальные пользователи доступны
	mode = acl.get(socket, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";

	mode = acl.get(process, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
}

class ACLWithUnixAccess : public ACLUnit {
protected:
	ACL<Resource, Client, UnixMode> acl;

	void SetUp() override {
		// root пользователь имеет доступ ко всем ресурсам.
		acl.add(folder, root, UnixMode::write);
		acl.add(file, root, UnixMode::read);
		acl.add(socket, root, UnixMode::view);
		acl.add(process, root, UnixMode::write);

		// guest пользователь не имеет доступа ни к чему
		acl.add(folder, guest, UnixMode::deny);
		acl.add(file, guest, UnixMode::deny);
		acl.add(socket, guest, UnixMode::deny);
		acl.add(process, guest, UnixMode::deny);

		// пользователи admin и user имеют смешанный доступ
		acl.add(folder, admin, UnixMode::deny);
		acl.add(file, admin, UnixMode::write);
		acl.add(socket, admin, UnixMode::write);
		acl.add(process, admin, UnixMode::deny);

		acl.add(folder, user, UnixMode::write);
		acl.add(file, user, UnixMode::deny);
		acl.add(socket, user, UnixMode::deny);
		acl.add(process, user, UnixMode::write);
	}
};

TEST_F(ACLWithUnixAccess, adding_and_getting) {
	// проверяем пользователя root
	auto mode = acl.get(folder, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());

	mode = acl.get(file, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::read, mode.unwrap());

	mode = acl.get(socket, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::view, mode.unwrap());

	mode = acl.get(process, root);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());

	// проверяем пользователя guest
	mode = acl.get(folder, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(file, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(socket, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(process, guest);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	// проверяем пользователя admin
	mode = acl.get(folder, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(file, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());

	mode = acl.get(socket, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());

	mode = acl.get(process, admin);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	// проверяем пользователя user
	mode = acl.get(folder, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());

	mode = acl.get(file, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(socket, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::deny, mode.unwrap());

	mode = acl.get(process, user);
	ASSERT_TRUE(mode.isOk()) << "Method ACL::get must return Ok but we got Err";
	EXPECT_EQ(UnixMode::write, mode.unwrap());
}

int main(int argc, char** argv) {
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
