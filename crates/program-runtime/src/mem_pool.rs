use {
    solana_compute_budget::{
        compute_budget::{MAX_CALL_DEPTH, MAX_INSTRUCTION_STACK_DEPTH, STACK_FRAME_SIZE},
        compute_budget_limits::{MAX_HEAP_FRAME_BYTES, MIN_HEAP_FRAME_BYTES},
    },
    solana_sbpf::{aligned_memory::AlignedMemory, ebpf::HOST_ALIGN},
    std::array,
};

trait Reset {
    fn reset(&mut self);
}

struct Pool<T: Reset, const SIZE: usize> {
    items: [Option<T>; SIZE],
    next_empty: usize,
}

impl<T: Reset, const SIZE: usize> Pool<T, SIZE> {
    fn new(items: [T; SIZE]) -> Self {
        Self {
            items: items.map(|i| Some(i)),
            next_empty: SIZE,
        }
    }

    fn len(&self) -> usize {
        SIZE
    }

    fn get(&mut self) -> Option<T> {
        if self.next_empty == 0 {
            return None;
        }
        self.next_empty = self.next_empty.saturating_sub(1);
        self.items
            .get_mut(self.next_empty)
            .and_then(|item| item.take())
    }

    fn put(&mut self, mut value: T) -> bool {
        self.items
            .get_mut(self.next_empty)
            .map(|item| {
                value.reset();
                item.replace(value);
                self.next_empty = self.next_empty.saturating_add(1);
                true
            })
            .unwrap_or(false)
    }
}

impl Reset for AlignedMemory<{ HOST_ALIGN }> {
    fn reset(&mut self) {
        self.as_slice_mut().fill(0)
    }
}

pub struct VmMemoryPool {
    stack: Pool<AlignedMemory<{ HOST_ALIGN }>, MAX_INSTRUCTION_STACK_DEPTH>,
    heap: Pool<AlignedMemory<{ HOST_ALIGN }>, MAX_INSTRUCTION_STACK_DEPTH>,
}

impl VmMemoryPool {
    pub fn new() -> Self {
        Self {
            stack: Pool::new(array::from_fn(|_| {
                AlignedMemory::zero_filled(STACK_FRAME_SIZE * MAX_CALL_DEPTH)
            })),
            heap: Pool::new(array::from_fn(|_| {
                AlignedMemory::zero_filled(MAX_HEAP_FRAME_BYTES as usize)
            })),
        }
    }

    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    pub fn heap_len(&self) -> usize {
        self.heap.len()
    }

    pub fn get_stack(&mut self, size: usize) -> AlignedMemory<{ HOST_ALIGN }> {
        debug_assert!(size == STACK_FRAME_SIZE * MAX_CALL_DEPTH);
        self.stack
            .get()
            .unwrap_or_else(|| AlignedMemory::zero_filled(size))
    }

    pub fn put_stack(&mut self, stack: AlignedMemory<{ HOST_ALIGN }>) -> bool {
        self.stack.put(stack)
    }

    pub fn get_heap(&mut self, heap_size: u32) -> AlignedMemory<{ HOST_ALIGN }> {
        debug_assert!((MIN_HEAP_FRAME_BYTES..=MAX_HEAP_FRAME_BYTES).contains(&heap_size));
        self.heap
            .get()
            .unwrap_or_else(|| AlignedMemory::zero_filled(MAX_HEAP_FRAME_BYTES as usize))
    }

    pub fn put_heap(&mut self, heap: AlignedMemory<{ HOST_ALIGN }>) -> bool {
        let heap_size = heap.len();
        debug_assert!(
            heap_size >= MIN_HEAP_FRAME_BYTES as usize
                && heap_size <= MAX_HEAP_FRAME_BYTES as usize
        );
        self.heap.put(heap)
    }
}

impl Default for VmMemoryPool {
    fn default() -> Self {
        Self::new()
    }
}
