package com.devsuperior.dscommerce.dto;

import com.devsuperior.dscommerce.entities.Order;
import com.devsuperior.dscommerce.entities.OrderItem;
import com.devsuperior.dscommerce.entities.OrderStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class OrderDTO {

    private Long id;
    private Instant moment;
    private OrderStatus status;

    private ClientDTO client;

    private PaymentDTO payment;

    List<OrderItemDTO> items = new ArrayList<>();

    public OrderDTO(Long id, PaymentDTO payment, ClientDTO client, OrderStatus status, Instant moment) {
        this.id = id;
        this.payment = payment;
        this.client = client;
        this.status = status;
        this.moment = moment;
    }

    public OrderDTO(Order entity) {
        id = entity.getId();
        payment = (entity.getPayment() == null) ? null : new PaymentDTO(entity.getPayment());
        client = new ClientDTO(entity.getClient());
        status = entity.getStatus();
        moment = entity.getMoment();
        for (OrderItem item : entity.getItems()) {
            OrderItemDTO itemDTO = new OrderItemDTO(item);
            items.add(itemDTO);
        }
    }

    public Long getId() {
        return id;
    }

    public List<OrderItemDTO> getItems() {
        return items;
    }

    public PaymentDTO getPayment() {
        return payment;
    }

    public ClientDTO getClient() {
        return client;
    }

    public OrderStatus getStatus() {
        return status;
    }

    public Instant getMoment() {
        return moment;
    }

    public Double getTotal() {

        double sum = 0.0;
        for (OrderItemDTO item : items) {
            sum += item.getSubTotal();
        }
        return sum;
    }

}
