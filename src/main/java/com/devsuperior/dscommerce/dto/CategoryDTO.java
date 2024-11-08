package com.devsuperior.dscommerce.dto;

import com.devsuperior.dscommerce.entities.Category;

public class CategoryDTO {

    private Long id;
    private String name;

    // contructors

    public CategoryDTO(String name, Long id) {
        this.name = name;
        this.id = id;
    }

    public CategoryDTO(Category entity) {
        name = entity.getName();
        id = entity.getId();
    }


    // getters
    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
