package com.in28minutes.rest.webservices.restfulwebservices.todo;

import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public class TodoJpaService {
        private TodoRepository repo;

    public TodoJpaService(TodoRepository repo) {
        this.repo = repo;
    }

    public List<Todo> findByUsername(String username){

            return repo.findByUsername(username);
        }

        public Todo addTodo(String username, String goal, LocalDate targetDate, boolean done) {
            Todo newTodo=new Todo(username,goal,targetDate,false);
            repo.save(newTodo);
            return newTodo;
        }

        public void deleteById(int id) {
            repo.deleteById(id);
        }

        public Todo findById(int id) {
            return repo.findById(id).orElse(null);
        }

        public void updateTodo(int id,Todo todo) {
            Todo updatingTodo=repo.findById(id).orElse(null);
            assert updatingTodo != null;
            updatingTodo.setDescription(todo.getDescription());
            updatingTodo.setTargetDate(todo.getTargetDate());
            repo.save(updatingTodo);
        }
    }

