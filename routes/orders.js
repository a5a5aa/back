import { Router } from 'express'
import admin from '../middleware/admin.js'
import { jwt } from '../middleware/auth.js'
import { createOrder, getMyOrders, getAllOrders } from '../controllers/orders.js'

const router = Router()

router.post('/', jwt, createOrder)
router.get('/', jwt, getMyOrders)
router.get('/all', jwt, admin, getAllOrders)

export default router
