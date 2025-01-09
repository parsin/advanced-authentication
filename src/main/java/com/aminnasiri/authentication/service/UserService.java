package com.aminnasiri.authentication.service;

import com.aminnasiri.authentication.dto.UserDto;
import com.aminnasiri.authentication.entity.User;
import com.aminnasiri.authentication.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Transactional
@Service
@RequiredArgsConstructor
public class UserService  {

    private final UserRepository userRepository;

    public User getUser(String username){
        Optional<User> user = userRepository.findByUsername(username);
        if (!user.isPresent()) {
            return null;
        }
        return user.get();
    }

    public void save(User user) {
        userRepository.save(user);
    }

}
