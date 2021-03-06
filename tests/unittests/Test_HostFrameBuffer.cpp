#include "UnitTest.hpp"
#include <PF_Net/Detail/HostFrameBuffer.hpp>

using namespace pf::net;
using namespace pf::net::detail;

PFTEST_CREATE(HostFrameBufferFreeList_General)
{
    HostFrameBufferFreeList free_list;

    unique_ptr<HostFrameBuffer> buffer = free_list.get();
    PFTEST_EXPECT(!buffer);

    buffer = free_list.get_or_make();
    PFTEST_EXPECT(buffer);

    HostFrameBuffer* raw_ptr = buffer.get();

    free_list.submit(std::move(buffer));
    buffer = free_list.get();
    PFTEST_EXPECT(buffer);
    PFTEST_EXPECT(buffer.get() == raw_ptr);

    free_list.submit(std::move(buffer));
    buffer = free_list.get_or_make();
    PFTEST_EXPECT(buffer);
    PFTEST_EXPECT(buffer.get() == raw_ptr);
}

PFTEST_CREATE(HostFrameBufferPendingList_General)
{
    HostFrameBufferPendingList pending_list(4);

    unique_ptr<HostFrameBuffer> buffer = pending_list.get();
    PFTEST_EXPECT(!buffer);

    unique_ptr<HostFrameBuffer> buffer_1 = make_unique<HostFrameBuffer>();
    unique_ptr<HostFrameBuffer> buffer_2 = make_unique<HostFrameBuffer>();
    unique_ptr<HostFrameBuffer> buffer_3 = make_unique<HostFrameBuffer>();
    unique_ptr<HostFrameBuffer> buffer_4 = make_unique<HostFrameBuffer>();
    unique_ptr<HostFrameBuffer> buffer_5 = make_unique<HostFrameBuffer>();
    unique_ptr<HostFrameBuffer> buffer_6 = make_unique<HostFrameBuffer>();

    HostFrameBuffer* buffer_1_raw = buffer_1.get();
    HostFrameBuffer* buffer_2_raw = buffer_2.get();
    HostFrameBuffer* buffer_3_raw = buffer_3.get();
    HostFrameBuffer* buffer_4_raw = buffer_4.get();
    HostFrameBuffer* buffer_5_raw = buffer_5.get();
    HostFrameBuffer* buffer_6_raw = buffer_6.get();


    buffer = pending_list.submit(std::move(buffer_1));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_2));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_3));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_4));
    PFTEST_EXPECT(!buffer);


    buffer_1 = pending_list.get();
    PFTEST_EXPECT(buffer_1.get() == buffer_1_raw);

    buffer_2 = pending_list.get();
    PFTEST_EXPECT(buffer_2.get() == buffer_2_raw);

    buffer_3 = pending_list.get();
    PFTEST_EXPECT(buffer_3.get() == buffer_3_raw);

    buffer_4 = pending_list.get();
    PFTEST_EXPECT(buffer_4.get() == buffer_4_raw);


    buffer = pending_list.submit(std::move(buffer_1));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_2));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_3));
    PFTEST_EXPECT(!buffer);

    buffer = pending_list.submit(std::move(buffer_4));
    PFTEST_EXPECT(!buffer);


    buffer_1 = pending_list.submit(std::move(buffer_5));
    PFTEST_EXPECT(buffer_1);
    PFTEST_EXPECT(buffer_1.get() == buffer_1_raw);

    buffer_2 = pending_list.submit(std::move(buffer_6));
    PFTEST_EXPECT(buffer_2);
    PFTEST_EXPECT(buffer_2.get() == buffer_2_raw);
}

PFTEST_CREATE(HostFrameBufferPendingList_MultipleGets)
{
    unique_ptr<HostFrameBuffer> buffer_1 = make_unique<HostFrameBuffer>();

    HostFrameBufferPendingList pending_list(50000);

    PFTEST_EXPECT(!pending_list.get());

    pending_list.submit(std::move(buffer_1));
    buffer_1 = pending_list.get();
    PFTEST_EXPECT(buffer_1);

    PFTEST_EXPECT(!pending_list.get());
    PFTEST_EXPECT(!pending_list.get());
    PFTEST_EXPECT(!pending_list.get());

    pending_list.submit(std::move(buffer_1));
    buffer_1 = pending_list.get();
    PFTEST_EXPECT(buffer_1);
}
