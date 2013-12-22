#ifndef QUEUE_HPP
#define QUEUE_HPP

#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>

template <typename T>
class Queue
{
public:
  T dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (queue_.empty())
      cond_.wait(lock);

    T top = queue_.front();
    queue_.pop_front();
    return top;
  }

  void enqueue(T value) {
    std::unique_lock<std::mutex> lock(mutex_);
    queue_.push_back(value);
    cond_.notify_all();
    return;
  }

private:
  std::deque<T> queue_;
  std::mutex mutex_;
  std::condition_variable cond_;
};

#endif // QUEUE_HPP
