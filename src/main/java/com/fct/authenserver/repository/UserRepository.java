package com.fct.authenserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.fct.authenserver.entity.*;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User,Integer>{
    //Buscar por username , optional , puede devolver user o null
    Optional<User> findByUsername(String username);
}
