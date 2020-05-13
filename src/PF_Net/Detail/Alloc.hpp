#pragma once

#include <PF_Net/Net.hpp>
#include <PF_Net/Detail/Export.hpp>

#include <memory>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

namespace pf::net::detail
{

void set_custom_allocators(CustomAllocators allocators);
CustomAllocators get_custom_allocators();

PFNET_API void* custom_alloc(size_t len);
PFNET_API void custom_free(void* data);

template <typename T>
class custom_stl_alloc
{
public:
    using value_type = T;
    using reference = T&;
    using const_reference = const T&;
    using size_type = size_t;

    custom_stl_alloc() = default;

    template <class T2>
    custom_stl_alloc(const custom_stl_alloc<T2>&)
    { }

    T* allocate(size_t count)
    {
        return (T*)custom_alloc(sizeof(T) * count);
    }

    void deallocate(T* elem, size_t)
    {
        custom_free(elem);
    }
};

template <typename T>
struct custom_stl_deleter
{
    void operator()(T* elem) const
    {
        elem->~T();
        custom_free(elem);
    }
};

template <class T, class U>
bool operator==(const custom_stl_alloc<T>&, const custom_stl_alloc<U>&) { return true; }
template <class T, class U>
bool operator!=(const custom_stl_alloc<T>&, const custom_stl_alloc<U>&) { return false; }

template <typename T>
using vector = std::vector<T, custom_stl_alloc<T>>;

template <typename T>
using unique_ptr = std::unique_ptr<T, custom_stl_deleter<T>>;

template <typename T>
using shared_ptr = std::shared_ptr<T>;

template <typename T>
using deque = std::deque<T, custom_stl_alloc<T>>;

template <typename T>
using queue = std::queue<T, deque<T>>;

template <typename Key, typename T>
using unordered_map = std::unordered_map<Key,
    T,
    std::hash<Key>, 
    std::equal_to<Key>, 
    custom_stl_alloc<std::pair<const Key, T>>>;

using string = std::basic_string<char, std::char_traits<char>, custom_stl_alloc<char>>;

template <typename T, typename ... Args>
T* custom_new(Args&& ... args)
{
    void* mem = custom_alloc(sizeof(T));
    return new (mem) T(args ...);
}

template <typename T>
void custom_delete(T elem)
{
    elem.~T();
    custom_free(elem);
}

template <typename T>
unique_ptr<T> make_unique()
{
    return unique_ptr<T>(custom_new<T>());
}

template <typename T, typename ... Args>
unique_ptr<T> make_unique(Args&& ... args)
{
    return unique_ptr<T>(custom_new<T>(std::forward<Args>(args)...));
}

template <typename T>
shared_ptr<T> make_shared()
{
    return shared_ptr<T>(custom_new<T>(), custom_stl_deleter<T>());
}

template <typename T, typename ... Args>
shared_ptr<T> make_shared(Args&& ... args)
{
    return shared_ptr<T>(custom_new<T>(std::forward<Args>(args)...), custom_stl_deleter<T>());
}

}
